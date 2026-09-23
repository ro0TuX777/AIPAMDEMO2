import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useNavigate } from "react-router-dom";
import { ChatPage } from "../../../src/pages/ChatPage";
import type { JobGetResponse, JobStatus } from "../../../src/api/types";
import "../../../src/index.css";

const jobId = "chat-lifecycle-e2e";
const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 30_000, refetchOnWindowFocus: false } } });

declare global {
  interface Window {
    setHarnessJobStatus: (status: JobStatus) => void;
    setHarnessJobId: (jobId: string) => void;
  }
}

window.setHarnessJobStatus = status => {
  client.setQueryData<JobGetResponse>(["job", jobId], current => current && ({ ...current, job: { ...current.job, status } }));
};

function HarnessNavigation() {
  const navigate = useNavigate();
  React.useEffect(() => {
    window.setHarnessJobId = nextJobId => navigate(`/jobs/${nextJobId}/chat`);
  }, [navigate]);
  return null;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <QueryClientProvider client={client}>
    <MemoryRouter initialEntries={[`/jobs/${jobId}/chat`]}>
      <HarnessNavigation />
      <Routes><Route path="/jobs/:jobId/chat" element={<ChatPage />} /></Routes>
    </MemoryRouter>
  </QueryClientProvider>,
);
