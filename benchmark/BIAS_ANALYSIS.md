# Analysis of "Loader" Type Bias

The latest benchmark revealed a 73% bias towards predicting the "Loader" malware type. Our investigation into the training data and inference configuration has identified several contributing factors.

## Findings

### 1. Training Data Imbalance
*   **Older Malware (e.g., Virut, Zeus, Cridex):** ~4,500 traffic samples each.
*   **Modern Malware (e.g., DarkGate, Lumma_Stealer, Pikabot):** ~500–700 traffic samples each.
*   **The Bias:** While the model has more data for older malware, the benchmark test set likely consists of modern samples. Within the "modern" category, Loaders like `DarkGate` and `Pikabot` have high-quality, distinctive patterns that the model may be over-indexing on as the "default" for modern malicious traffic.

### 2. Category List in Prompt
*   The `MALWARE_CATEGORIES` list in the inference prompt includes a high density of specific Loader families (8 Loaders vs 8 Infostealers). 
*   If the model is uncertain but detects modern features, it has many "Loader" options to choose from, increasing the likelihood of a Loader prediction.

### 3. Structural Similarities
*   Many Infostealers use Loader-like behavior in their initial stages (e.g., fetching a second-stage payload). The model may be correctly identifying this behavior but incorrectly labeling it as the primary family/type.

## Proposed Improvements

| Improvement | Rationale |
|-------------|-----------|
| **Data Augmentation** | Increase traffic samples for `Infostealer` and `RAT` families to match the 4,500+ count of older families. |
| **Prompt Engineering** | Add **Malware Type** (Loader, Stealer, RAT, etc.) directly to the candidate list in the prompt to allow the model to classify at the type level first. |
| **Category Shuffling** | Randomize the order of categories in the prompt to ensure the model isn't biased by list position. |
| **Two-Stage Inference** | First classify as "Malicious/Benign", then "Malware Type", then finally "Specific Family". |

## Conclusion
The 100% malicious detection rate is excellent. The "Loader" bias is likely a side effect of the model being well-trained on a few very high-quality modern loader samples while lacking comparable volume for modern stealers and rats.
