#!/usr/bin/env python3
"""
Test the fine-tuned traffic analysis model using real training data samples.
"""

import json
import random
from pathlib import Path

def load_test_samples():
    """Load real samples from the training data for testing."""
    test_samples = []

    # Load samples from different datasets
    dataset_files = [
        ("data/trafficllm_datasets/ustc-tfc-2016/ustc-tfc-2016_detection_packet_train.json", "Malware Detection"),
        ("data/trafficllm_datasets/iscx-vpn-2016/iscx-vpn-2016_detection_packet_train.json", "VPN Detection"),
        ("data/trafficllm_datasets/iscx-tor-2016/iscx-tor-2016_detection_packet_train.json", "Tor Detection"),
    ]

    for filepath, task_name in dataset_files:
        path = Path(filepath)
        if path.exists():
            with open(path) as f:
                samples = []
                for i, line in enumerate(f):
                    if i >= 100:  # Only check first 100 lines
                        break
                    try:
                        sample = json.loads(line)
                        samples.append({
                            "task": task_name,
                            "instruction": sample["instruction"],
                            "expected": sample["output"]
                        })
                    except:
                        continue
                # Pick 2 random samples from each dataset
                if samples:
                    test_samples.extend(random.sample(samples, min(2, len(samples))))

    return test_samples


# Fallback test cases if no training data found
TEST_CASES = []


SYSTEM_PROMPT = "You are a network traffic analysis expert. Analyze the provided packet data and classify the traffic type or detect malicious activity. Provide concise, accurate classifications."


def run_tests():
    """Run all test cases."""
    from mlx_lm import load, generate

    print("=" * 70)
    print("Testing Fine-tuned Traffic Analysis Model")
    print("=" * 70)

    # Load test samples from real training data
    test_cases = load_test_samples()
    if not test_cases:
        print("No training data found for testing!")
        return

    print(f"\nLoaded {len(test_cases)} test samples from training data")

    print("\nLoading model...")
    model, tokenizer = load(
        "mlx-community/Meta-Llama-3.1-8B-Instruct-4bit",
        adapter_path="models/aipam-llama-mlx/adapters"
    )
    print("Model loaded!\n")

    results = []
    correct = 0

    for i, test in enumerate(test_cases, 1):
        print(f"\n[Test {i}/{len(test_cases)}] {test['task']}")
        print(f"Expected: {test['expected']}")

        # Truncate very long prompts for display
        prompt_preview = test["instruction"][:200] + "..." if len(test["instruction"]) > 200 else test["instruction"]
        print(f"Prompt: {prompt_preview}")

        # Apply chat template like training data
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": test["instruction"]}
        ]
        formatted_prompt = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )

        response = generate(
            model, tokenizer,
            prompt=formatted_prompt,
            max_tokens=15,  # Short response expected (just label)
            verbose=False
        )

        response_clean = response.strip()
        print(f"Response: {response_clean}")

        # Check if response matches expected
        is_correct = test["expected"].lower() in response_clean.lower()
        if is_correct:
            correct += 1
            print("✅ CORRECT")
        else:
            print("❌ INCORRECT")

        results.append({
            "task": test["task"],
            "expected": test["expected"],
            "response": response_clean,
            "correct": is_correct
        })

    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)

    for i, r in enumerate(results, 1):
        status = "✅" if r["correct"] else "❌"
        print(f"{status} [{r['task'][:20]:20}] Expected: {r['expected']:15} | Got: {r['response'][:30]}")

    accuracy = correct / len(results) * 100 if results else 0
    print(f"\nAccuracy: {correct}/{len(results)} ({accuracy:.1f}%)")

    # Save results
    with open("test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to test_results.json")


if __name__ == "__main__":
    run_tests()

