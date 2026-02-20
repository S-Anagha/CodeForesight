from __future__ import annotations

from codeforesight.stages.stage3_temporal import train_temporal_model


def main() -> None:
    meta = train_temporal_model()
    print(
        "Trained Stage 3 temporal + timeline models. "
        f"Window={meta['window']} months, samples={meta['months']} months."
    )


if __name__ == "__main__":
    main()
