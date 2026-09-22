// Public API entry point. Keep page and hook imports stable as domains evolve.
export * from "./api/types";
export { ApiError, isDemoMode, setApiToken } from "./api/transport";

import { uploadsApi } from "./api/uploads";
import { jobsApi } from "./api/jobs";
import { bluescrubApi } from "./api/bluescrub";
import { hostsApi } from "./api/hosts";
import { binaryApi } from "./api/binary";
import { eventsApi } from "./api/events";
import { investigationApi } from "./api/investigation";
import { reportsApi } from "./api/reports";
import { systemApi } from "./api/system";
import { temporalApi } from "./api/temporal";
import { integrationsApi } from "./api/integrations";
import { knowledgeBaseApi } from "./api/knowledge-base";
import { chatApi } from "./api/chat";
import { rulesApi } from "./api/rules";
import { trainingApi } from "./api/training";

export const api = {
  ...uploadsApi,
  ...jobsApi,
  ...bluescrubApi,
  ...hostsApi,
  ...binaryApi,
  ...eventsApi,
  ...investigationApi,
  ...reportsApi,
  ...systemApi,
  ...temporalApi,
  ...integrationsApi,
  ...knowledgeBaseApi,
  ...chatApi,
  ...rulesApi,
  ...trainingApi,
};
