import type {
  BlueScrubProject,
  BlueScrubLineage,
  BlueScrubBindResult,
  DacvMetrics,
} from "./types";
import {
  get,
  post,
  put,
} from "./transport";

export const bluescrubApi = {
  listBlueScrubProjects(): Promise<BlueScrubProject[]> {
    return get<BlueScrubProject[]>("/bluescrub/projects");
  },

  createBlueScrubProject(display_name: string): Promise<BlueScrubProject> {
    return post<BlueScrubProject>("/bluescrub/projects", { display_name });
  },

  /** Bind an ad-hoc code-artifact job to a project. No re-scan; carry-forward
   *  applies from the next scan onward. */
  bindJobToProject(
    jobId: string,
    body: { project_id?: string; display_name?: string; actor?: string },
  ): Promise<BlueScrubBindResult> {
    return put<BlueScrubBindResult>(`/bluescrub/jobs/${jobId}/project`, body);
  },

  getDacvReport(jobId: string): Promise<{ dacv: DacvMetrics; lineage?: BlueScrubLineage }> {
    return get<{ dacv: DacvMetrics; lineage?: BlueScrubLineage }>(`/bluescrub/report/${jobId}`);
  },
};
