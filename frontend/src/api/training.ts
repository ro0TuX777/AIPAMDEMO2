import type {
  TrainingConfig,
  TrainingStatus,
  TrainingLedgerResponse,
  TrainingSummary,
  ExportStatus,
  DistillConfig,
  DistillConfigUpdate,
  DistillStats,
} from "./types";
import {
  get,
  post,
} from "./transport";

export const trainingApi = {
  /** @deprecated V1 */
  startTrainingJob(): Promise<any> { return post<any>("/training/start"); },

  /** @deprecated V1 */
  getTrainingSummary(): Promise<TrainingSummary> { return get<TrainingSummary>("/training/summary"); },

  /** @deprecated V1 */
  getTrainingLedger(): Promise<TrainingLedgerResponse> { return get<TrainingLedgerResponse>("/training/ledger"); },

  /** @deprecated V1 */
  getTrainingConfig(): Promise<TrainingConfig> { return get<TrainingConfig>("/training/config"); },

  /** @deprecated V1 */
  getTrainingStatus(): Promise<TrainingStatus> { return get<TrainingStatus>("/training/status"); },

  /** @deprecated V1 */
  pauseTraining(): Promise<any> { return post<any>("/training/pause"); },

  /** @deprecated V1 */
  stopTraining(): Promise<any> { return post<any>("/training/stop"); },

  getDistillConfig(): Promise<DistillConfig> { return get<DistillConfig>("/training/distill/config"); },

  updateDistillConfig(cfg: Partial<DistillConfigUpdate>): Promise<any> { return post<any>("/training/distill/config", cfg); },

  getDistillStats(): Promise<DistillStats> { return get<DistillStats>("/training/distill/stats"); },

  testTeacher(): Promise<any> { return post<any>("/training/distill/test"); },

  exportModel(): Promise<any> { return post<any>("/training/export"); },

  getExportStatus(): Promise<ExportStatus> { return get<ExportStatus>("/training/export/status"); },
};
