export type EndpointStatus = "active" | "starting" | "inactive" | "error";

export type Endpoint = {
  id: string;
  port: number;
  allow_management: boolean;
  allow_proxy: boolean;
  require_proxy_auth_info: boolean;
  allow_http_forward: boolean;
  allow_http_reverse: boolean;
  allow_socks5: boolean;
  source: "environment" | "database";
  read_only: boolean;
  status: EndpointStatus;
  last_error?: string;
  created_at?: string;
  updated_at?: string;
};

export type EndpointInput = {
  port: number;
  allow_management: boolean;
  allow_proxy: boolean;
  require_proxy_auth_info: boolean;
  allow_http_forward: boolean;
  allow_http_reverse: boolean;
  allow_socks5: boolean;
};

export type EndpointListResponse = {
  items: Endpoint[];
};
