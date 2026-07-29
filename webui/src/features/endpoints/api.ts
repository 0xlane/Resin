import { apiRequest } from "../../lib/api-client";
import type { Endpoint, EndpointInput, EndpointListResponse } from "./types";

const path = "/api/v1/endpoints";

export async function listEndpoints(): Promise<Endpoint[]> {
  const response = await apiRequest<EndpointListResponse>(path);
  return response.items ?? [];
}

export async function createEndpoint(input: EndpointInput): Promise<Endpoint> {
  return await apiRequest<Endpoint>(path, {
    method: "POST",
    body: { ...input },
  });
}

export async function updateEndpoint(id: string, input: EndpointInput): Promise<Endpoint> {
  return await apiRequest<Endpoint>(`${path}/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: { ...input },
  });
}

export async function deleteEndpoint(id: string): Promise<void> {
  await apiRequest<void>(`${path}/${encodeURIComponent(id)}`, { method: "DELETE" });
}
