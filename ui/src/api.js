export async function startRun(formData) {
  const response = await fetch("/api/run", {
    method: "POST",
    body: formData,
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || "Failed to start job");
  }
  return response.json();
}

export async function startSampleRun(payload) {
  const response = await fetch("/api/run-sample", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams(payload),
  });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || "Failed to start sample job");
  }
  return response.json();
}

export async function getStatus(jobId) {
  const response = await fetch(`/api/status/${jobId}`);
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || "Failed to fetch status");
  }
  return response.json();
}

export function downloadUrl(jobId) {
  return `/api/download/${jobId}`;
}
