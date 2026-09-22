import type {
  SigmaDetectionListResponse,
  SigmaAnalyzeResponse,
  SuricataRuleItem,
  ParsedRuleListResponse,
  RuleFileStats,
  ToggleRulesRequest,
  RuleType,
  GeneratedRuleResponse,
} from "./types";
import {
  qs,
  get,
  post,
  del,
  put,
} from "./transport";

export const rulesApi = {
  listSigmaDetections(jobId: string): Promise<SigmaDetectionListResponse> {
    return get<SigmaDetectionListResponse>(`/jobs/${jobId}/sigma`);
  },

  analyzeSigma(jobId: string): Promise<SigmaAnalyzeResponse> {
    return post<SigmaAnalyzeResponse>(`/jobs/${jobId}/sigma/analyze`, {});
  },

  listSuricataRules(): Promise<SuricataRuleItem[]> {
    return get<SuricataRuleItem[]>("/rules/suricata");
  },

  getSuricataRule(filename: string): Promise<SuricataRuleItem> {
    return get<SuricataRuleItem>(`/rules/suricata/${filename}`);
  },

  updateSuricataRule(filename: string, content: string): Promise<SuricataRuleItem> {
    return put<SuricataRuleItem>(`/rules/suricata/${filename}`, { content });
  },

  deleteSuricataRule(filename: string): Promise<void> {
    return del<void>(`/rules/suricata/${filename}`);
  },

  getRuleFileStats(filename: string): Promise<RuleFileStats> {
    return get<RuleFileStats>(`/rules/suricata/${filename}/stats`);
  },

  getParsedRules(filename: string, params: {
    search?: string; category?: string; enabled?: boolean;
    severity?: number; offset?: number; limit?: number;
  } = {}): Promise<ParsedRuleListResponse> {
    return get<ParsedRuleListResponse>(`/rules/suricata/${filename}/parsed${qs(params)}`);
  },

  toggleRules(filename: string, body: ToggleRulesRequest): Promise<{ changed: number; total_targeted: number; enabled: boolean }> {
    return post<{ changed: number; total_targeted: number; enabled: boolean }>(`/rules/suricata/${filename}/toggle`, body);
  },

  generateRule(jobId: string, findingId: string, ruleType: RuleType): Promise<GeneratedRuleResponse> {
    return post<GeneratedRuleResponse>(`/jobs/${jobId}/findings/${findingId}/generate-rule`, { rule_type: ruleType });
  },
};
