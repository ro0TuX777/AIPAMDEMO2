import importlib.util
from pathlib import Path
from types import SimpleNamespace


MODULE_PATH = Path(__file__).resolve().parents[3] / "finetuning" / "finetune_llama.py"
SPEC = importlib.util.spec_from_file_location("finetune_llama", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_validate_training_samples_accepts_chatml_examples() -> None:
    samples = [
        {
            "messages": [
                {"role": "system", "content": "You are a helpful analyst."},
                {"role": "user", "content": "Summarize the artifact."},
                {"role": "assistant", "content": "The artifact appears suspicious."},
            ]
        }
    ]

    validated = MODULE.validate_training_samples(samples)

    assert validated is not None
    assert len(validated) == 1


def test_build_training_args_uses_sft_config_without_checkpoint_saves() -> None:
    args = SimpleNamespace(
        batch_size=1,
        iters=200,
        epochs=1,
        learning_rate=5e-5,
        output="models/demo",
    )

    training_args = MODULE.build_training_args(args)

    assert training_args.output_dir == "models/demo"
    assert training_args.max_steps == 200
    assert training_args.save_strategy == "no"
