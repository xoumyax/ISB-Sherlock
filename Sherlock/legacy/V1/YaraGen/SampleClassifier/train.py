"""Training loop for the window-strided byte CNN (classifier B).

DDP-aware via ``torchrun``; only rank 0 logs, evaluates and checkpoints (house
convention across ``YaraGen/Training``).

Validation follows EXP2_DESIGN §4 and is not negotiable: the **binary** head is
scored on F_dev families plus a G_stats holdout, because unseen families are the
deployment condition -- the model will be asked to attribute families it never
trained on. The **family** head is scored on a within-F_train holdout, since F_dev
families have no class in the 23-way label space by construction.

Sweep variants come from the environment (``VAULT``, ``WINDOW``), and every
variant writes to its own directory: the pre-wipe clobbering incident happened
because only part of the output path was variant-isolated.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from typing import Any, Callable

import numpy as np
import torch
import torch.distributed as dist
from torch.nn.parallel import DistributedDataParallel
from torch.utils.data import DataLoader, DistributedSampler

from .data import FAMILY_UNLABELED, ClassifierDataspec, DataConfig, WindowSampler
from .dataset import WindowDataset, collate_windows
from .model import ModelConfig, WindowMalConv

__all__ = ["TrainConfig", "ClassifierTrainer", "variant_name"]

CONFIG: dict[str, Any] = {
    "epochs": 12,
    "batch_size": 8,
    "lr": 1e-3,
    "weight_decay": 1e-5,
    "warmup_steps": 100,
    "grad_clip": 1.0,
    "num_workers": 8,
    "amp": True,
    "log_every": 25,
    "seed": 20260809,

    # sweep axes (EXP2_DESIGN §4: 2 GPUs x 4 variants)
    "vault": False,
    "window_size": 262_144,
    "n_windows": 32,
    "stratify": "uniform",

    # Checkpoint selection WITHIN a run. Distinct from the sweep's variant-choice
    # criterion (F_dev binary AUC, pre-registered in EXP2_DESIGN §4 and unchanged).
    #
    # "combined" = binary_auc + family_top1, because attribution consumes BOTH
    # heads. The 2026-08-09 sweep showed the heads peak at different epochs --
    # binary AUC declines from overfitting while family top-1 keeps improving --
    # so selecting on binary AUC alone saved checkpoints with the family head near
    # its worst (up to 15 points of family top-1 given away).
    "checkpoint_selection": "combined",     # combined | binary_auc
    #: Also keep a per-epoch checkpoint, so a selection criterion can be revisited
    #: without retraining. The 2026-08-09 sweep could not be re-selected because
    #: only best/last survived.
    "save_every_epoch": False,

    "family_loss_weight": 0.5,
    "channels": 128,
    "kernel_size": 512,
    "stride": 512,
    "pooling": "attention",
}


class TrainConfig(dict):
    """CONFIG dict with env overrides (house style, no argparse)."""

    @classmethod
    def from_env(cls, base: dict[str, Any] | None = None) -> "TrainConfig":
        cfg = cls(dict(base or CONFIG))
        if os.environ.get("VAULT"):
            cfg["vault"] = os.environ["VAULT"].strip().lower() in ("in", "1", "true")
        if os.environ.get("WINDOW"):
            cfg["window_size"] = int(os.environ["WINDOW"])
        if os.environ.get("N_WINDOWS"):
            cfg["n_windows"] = int(os.environ["N_WINDOWS"])
        if os.environ.get("EPOCHS"):
            cfg["epochs"] = int(os.environ["EPOCHS"])
        if os.environ.get("BATCH_SIZE"):
            cfg["batch_size"] = int(os.environ["BATCH_SIZE"])
        if os.environ.get("STRATIFY"):
            cfg["stratify"] = os.environ["STRATIFY"]
        if os.environ.get("LIMIT"):
            cfg["limit"] = int(os.environ["LIMIT"])
        if os.environ.get("SAVE_EVERY_EPOCH"):
            cfg["save_every_epoch"] = True
        if os.environ.get("CHECKPOINT_SELECTION"):
            cfg["checkpoint_selection"] = os.environ["CHECKPOINT_SELECTION"]
        return cfg


def variant_name(config: dict[str, Any]) -> str:
    """Directory-safe variant id. Encodes every sweep axis, so no two variants
    can ever write to the same place."""
    vault = "vaultin" if config["vault"] else "vaultout"
    kb = config["window_size"] // 1024
    return f"{vault}__w{kb}k__n{config['n_windows']}__{config['stratify']}"


# --------------------------------------------------------------------------
# distributed helpers
# --------------------------------------------------------------------------

def _dist_info() -> tuple[int, int, int]:
    rank = int(os.environ.get("RANK", 0))
    world = int(os.environ.get("WORLD_SIZE", 1))
    local = int(os.environ.get("LOCAL_RANK", 0))
    return rank, world, local


def _is_distributed() -> bool:
    return int(os.environ.get("WORLD_SIZE", 1)) > 1


class ClassifierTrainer:
    """Trains :class:`~.model.WindowMalConv` on a :class:`ClassifierDataspec`."""

    def __init__(
        self,
        dataspec: ClassifierDataspec,
        config: dict[str, Any] | None = None,
        out_dir: str = "",
        sections_of: Callable[[str], Any] | None = None,
    ):
        self.dataspec = dataspec
        self.config = dict(config or CONFIG)
        self.out_dir = out_dir
        self.sections_of = sections_of
        self.rank, self.world, self.local_rank = _dist_info()

        torch.manual_seed(self.config["seed"] + self.rank)
        np.random.seed(self.config["seed"] + self.rank)

        if _is_distributed() and not dist.is_initialized():
            dist.init_process_group(backend="nccl")
        self.device = (torch.device(f"cuda:{self.local_rank}")
                       if torch.cuda.is_available() else torch.device("cpu"))
        if torch.cuda.is_available():
            torch.cuda.set_device(self.local_rank)

        self.sampler = WindowSampler(
            window_size=self.config["window_size"],
            n_windows=self.config["n_windows"],
            stratify=self.config["stratify"],
            seed=self.config["seed"],
        )

        model_config = ModelConfig(
            channels=self.config["channels"],
            kernel_size=self.config["kernel_size"],
            stride=self.config["stride"],
            n_families=len(dataspec.family_names),
            pooling=self.config["pooling"],
            family_loss_weight=self.config["family_loss_weight"],
        )
        self.model_config = model_config
        self.model = WindowMalConv(model_config).to(self.device)
        self.ddp = (
            DistributedDataParallel(self.model, device_ids=[self.local_rank])
            if _is_distributed() else self.model
        )

        # ~8:1 goodware:malware in the training mix; without this the binary head
        # can score well by leaning benign.
        n_pos = sum(1 for r in dataspec.train if r.label == 1)
        n_neg = len(dataspec.train) - n_pos
        self.pos_weight = torch.tensor(
            max(1.0, n_neg / max(1, n_pos)), device=self.device)

        self.optimizer = torch.optim.AdamW(
            self.model.parameters(), lr=self.config["lr"],
            weight_decay=self.config["weight_decay"])
        self.scaler = torch.amp.GradScaler(
            "cuda", enabled=bool(self.config["amp"]) and torch.cuda.is_available())
        self.step = 0

    # -- data ----------------------------------------------------------
    def _loader(self, refs, shuffle: bool, distributed: bool):
        dataset = WindowDataset(refs, self.sampler, self.sections_of)
        sampler = (DistributedSampler(dataset, shuffle=shuffle)
                   if distributed and _is_distributed() else None)
        loader = DataLoader(
            dataset,
            batch_size=self.config["batch_size"],
            shuffle=(shuffle and sampler is None),
            sampler=sampler,
            num_workers=self.config["num_workers"],
            collate_fn=collate_windows,
            pin_memory=torch.cuda.is_available(),
            drop_last=False,
        )
        return dataset, loader, sampler

    def log(self, msg: str) -> None:
        if self.rank == 0:
            print(msg, flush=True)

    # -- training ------------------------------------------------------
    def train(self) -> dict[str, Any]:
        refs = self.dataspec.train
        if self.config.get("limit"):
            refs = refs[: self.config["limit"]]
        dataset, loader, sampler = self._loader(refs, shuffle=True,
                                                distributed=True)

        self.log(f"[clf] variant={variant_name(self.config)} "
                 f"train={len(refs)} world={self.world} device={self.device}")
        history: list[dict[str, Any]] = []
        best = {"epoch": -1, "binary_auc": -1.0, "score": -1.0}
        best_auc = {"epoch": -1, "binary_auc": -1.0}

        for epoch in range(self.config["epochs"]):
            dataset.set_epoch(epoch)          # fresh window subset = augmentation
            if sampler is not None:
                sampler.set_epoch(epoch)
            self.ddp.train()

            started = time.time()
            totals = {"loss": 0.0, "loss_binary": 0.0, "loss_family": 0.0, "n": 0}
            for batch in loader:
                stats = self._train_step(batch)
                for key in ("loss", "loss_binary", "loss_family"):
                    totals[key] += stats[key]
                totals["n"] += 1
                if totals["n"] % self.config["log_every"] == 0:
                    self.log(f"[clf] e{epoch} step {totals['n']} "
                             f"loss={stats['loss']:.4f} "
                             f"(bin {stats['loss_binary']:.4f} "
                             f"fam {stats['loss_family']:.4f})")

            record: dict[str, Any] = {
                "epoch": epoch,
                "seconds": round(time.time() - started, 1),
                **{k: round(totals[k] / max(1, totals["n"]), 5)
                   for k in ("loss", "loss_binary", "loss_family")},
            }
            if self.rank == 0:
                record.update(self.evaluate())
                history.append(record)
                self.log(f"[clf] epoch {epoch}: {json.dumps(record)}")
                score = self._selection_score(record)
                record["selection_score"] = round(score, 5)
                if score > best["score"]:
                    best = {"epoch": epoch, "score": round(score, 5),
                            "binary_auc": record.get("binary_auc", -1.0),
                            "family_top1": record.get("family_top1")}
                    self.save("best")
                # Kept alongside, so the pre-registered variant-choice criterion
                # (F_dev binary AUC) stays directly readable off disk.
                if record.get("binary_auc", -1) > best_auc["binary_auc"]:
                    best_auc = {"epoch": epoch,
                                "binary_auc": record["binary_auc"],
                                "family_top1": record.get("family_top1")}
                    self.save("best_auc")
                if self.config.get("save_every_epoch"):
                    self.save(f"epoch{epoch:03d}")
                self.save("last")

        if self.rank == 0:
            self._write_report({"history": history, "best": best,
                                "best_binary_auc": best_auc})
        if _is_distributed():
            dist.barrier()
        return {"history": history, "best": best, "best_binary_auc": best_auc,
                "variant": variant_name(self.config)}

    def _selection_score(self, record: dict[str, Any]) -> float:
        """Checkpoint-selection score for one epoch's metrics."""
        auc = record.get("binary_auc")
        if auc is None:
            return -1.0
        if self.config.get("checkpoint_selection") == "binary_auc":
            return float(auc)
        return float(auc) + float(record.get("family_top1") or 0.0)

    def _train_step(self, batch: dict[str, Any]) -> dict[str, float]:
        windows = batch["windows"].to(self.device, non_blocking=True)
        mask = batch["mask"].to(self.device, non_blocking=True)
        labels = batch["labels"].to(self.device, non_blocking=True)
        family = batch["family"].to(self.device, non_blocking=True)
        weights = batch["weights"].to(self.device, non_blocking=True)

        self.optimizer.zero_grad(set_to_none=True)
        with torch.amp.autocast("cuda", enabled=self.scaler.is_enabled()):
            out = self.ddp(windows, mask)
            losses = (self.model.loss if not _is_distributed()
                      else self.ddp.module.loss)(
                out, labels, family, weights, self.pos_weight)

        self.scaler.scale(losses["loss"]).backward()
        if self.config["grad_clip"]:
            self.scaler.unscale_(self.optimizer)
            torch.nn.utils.clip_grad_norm_(self.model.parameters(),
                                           self.config["grad_clip"])
        self.scaler.step(self.optimizer)
        self.scaler.update()
        self.step += 1
        return {k: float(v.detach()) for k, v in losses.items()}

    # -- evaluation ----------------------------------------------------
    @torch.no_grad()
    def evaluate(self) -> dict[str, Any]:
        """Rank-0 only. Binary head on unseen families; family head in-dist."""
        from sklearn.metrics import roc_auc_score

        self.ddp.eval()
        out: dict[str, Any] = {}

        probs, labels = [], []
        _ds, loader, _s = self._loader(self.dataspec.val_binary, False, False)
        for batch in loader:
            logits = self.model(batch["windows"].to(self.device),
                                batch["mask"].to(self.device))["logit_binary"]
            probs.extend(torch.sigmoid(logits.float()).cpu().tolist())
            labels.extend(batch["labels"].tolist())
        if len(set(labels)) > 1:
            out["binary_auc"] = round(float(roc_auc_score(labels, probs)), 5)
            out["binary_n"] = len(labels)

        if self.dataspec.val_family:
            correct = top3 = total = 0
            _ds, loader, _s = self._loader(self.dataspec.val_family, False, False)
            for batch in loader:
                logits = self.model(batch["windows"].to(self.device),
                                    batch["mask"].to(self.device))["logits_family"]
                ranked = logits.float().argsort(dim=1, descending=True).cpu()
                for i, target in enumerate(batch["family"].tolist()):
                    if target == FAMILY_UNLABELED:
                        continue
                    total += 1
                    order = ranked[i].tolist()
                    correct += int(order[0] == target)
                    top3 += int(target in order[:3])
            if total:
                out["family_top1"] = round(correct / total, 5)
                out["family_top3"] = round(top3 / total, 5)
                out["family_n"] = total
        return out

    # -- persistence ---------------------------------------------------
    def save(self, tag: str) -> str | None:
        if self.rank != 0 or not self.out_dir:
            return None
        os.makedirs(self.out_dir, exist_ok=True)
        path = os.path.join(self.out_dir, f"{tag}.pt")
        torch.save({
            "model": self.model.state_dict(),
            "model_config": asdict(self.model_config),
            "train_config": dict(self.config),
            "family_names": self.dataspec.family_names,
            "sampler": asdict(self.sampler),
            "variant": variant_name(self.config),
        }, path)
        return path

    def _write_report(self, payload: dict[str, Any]) -> None:
        os.makedirs(self.out_dir, exist_ok=True)
        payload = dict(payload)
        payload["variant"] = variant_name(self.config)
        payload["config"] = dict(self.config)
        payload["dataspec"] = self.dataspec.summary()
        with open(os.path.join(self.out_dir, "report.json"), "w") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True, default=str)


def load_checkpoint(path: str, device: str = "cpu") -> tuple[WindowMalConv, dict]:
    """Rebuild a model from a checkpoint, config included."""
    blob = torch.load(path, map_location=device, weights_only=False)
    model = WindowMalConv(ModelConfig(**blob["model_config"]))
    model.load_state_dict(blob["model"])
    model.to(device).eval()
    return model, blob
