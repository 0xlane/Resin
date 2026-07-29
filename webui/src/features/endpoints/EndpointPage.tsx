import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  Check,
  LockKeyhole,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  X,
} from "lucide-react";
import { type FormEvent, useState } from "react";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { Input } from "../../components/ui/Input";
import { Switch } from "../../components/ui/Switch";
import { ToastContainer } from "../../components/ui/Toast";
import { useToast } from "../../hooks/useToast";
import { useI18n } from "../../i18n";
import { formatApiErrorMessage } from "../../lib/error-message";
import { getEnvConfig } from "../systemConfig/api";
import { createEndpoint, deleteEndpoint, listEndpoints, updateEndpoint } from "./api";
import type { Endpoint, EndpointInput, EndpointStatus } from "./types";

type EndpointDraft = Omit<EndpointInput, "port"> & { port: string };

const EMPTY_ENDPOINTS: Endpoint[] = [];

function endpointToDraft(endpoint: Endpoint): EndpointDraft {
  return {
    port: String(endpoint.port),
    allow_management: endpoint.allow_management,
    allow_proxy: endpoint.allow_proxy,
    require_proxy_auth_info: endpoint.require_proxy_auth_info,
    allow_http_forward: endpoint.allow_http_forward,
    allow_http_reverse: endpoint.allow_http_reverse,
    allow_socks5: endpoint.allow_socks5,
  };
}

function nextAvailablePort(endpoints: Endpoint[]): number {
  const occupied = new Set(endpoints.map((endpoint) => endpoint.port));
  const defaultPort = endpoints.find((endpoint) => endpoint.id === "default")?.port ?? 2260;
  for (let port = Math.min(defaultPort + 1, 65535); port <= 65535; port += 1) {
    if (!occupied.has(port)) {
      return port;
    }
  }
  for (let port = 1024; port < defaultPort; port += 1) {
    if (!occupied.has(port)) {
      return port;
    }
  }
  return 2261;
}

function newEndpointDraft(endpoints: Endpoint[]): EndpointDraft {
  return {
    port: String(nextAvailablePort(endpoints)),
    allow_management: false,
    allow_proxy: true,
    require_proxy_auth_info: false,
    allow_http_forward: true,
    allow_http_reverse: true,
    allow_socks5: true,
  };
}

function statusPresentation(status: EndpointStatus | string): {
  label: string;
  className: string;
} {
  switch (status) {
    case "active":
      return { label: "运行中", className: "endpoint-status-active" };
    case "starting":
      return { label: "启动中", className: "endpoint-status-starting" };
    case "error":
      return { label: "异常", className: "endpoint-status-error" };
    default:
      return { label: "未运行", className: "endpoint-status-inactive" };
  }
}

function enabledCapabilities(endpoint: Endpoint): string[] {
  const capabilities: string[] = [];
  if (endpoint.allow_management) capabilities.push("管理页面");
  if (endpoint.allow_proxy && endpoint.allow_http_forward) capabilities.push("HTTP 正向代理");
  if (endpoint.allow_proxy && endpoint.allow_http_reverse) capabilities.push("HTTP 反向代理");
  if (endpoint.allow_proxy && endpoint.allow_socks5) capabilities.push("SOCKS5 代理");
  return capabilities;
}

type EndpointEditorProps = {
  endpoint: Endpoint | null;
  draft: EndpointDraft;
  pending: boolean;
  onChange: (draft: EndpointDraft) => void;
  onClose: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
};

function EndpointEditor({
  endpoint,
  draft,
  pending,
  onChange,
  onClose,
  onSubmit,
}: EndpointEditorProps) {
  const { t } = useI18n();
  const editing = endpoint !== null;

  const setProxyEnabled = (enabled: boolean) => {
    if (!enabled) {
      onChange({
        ...draft,
        allow_proxy: false,
        require_proxy_auth_info: false,
        allow_http_forward: false,
        allow_http_reverse: false,
        allow_socks5: false,
      });
      return;
    }
    onChange({
      ...draft,
      allow_proxy: true,
      allow_http_forward: true,
      allow_http_reverse: true,
      allow_socks5: true,
    });
  };

  const setProtocol = (field: "allow_http_forward" | "allow_http_reverse" | "allow_socks5", enabled: boolean) => {
    const next = { ...draft, [field]: enabled };
    if (!next.allow_http_forward && !next.allow_socks5) {
      next.require_proxy_auth_info = false;
    }
    onChange(next);
  };

  return (
    <div className="drawer-overlay" role="dialog" aria-modal="true" onClick={onClose}>
      <Card className="drawer-panel endpoint-drawer" onClick={(event) => event.stopPropagation()}>
        <div className="drawer-header">
          <h3>{editing ? t("编辑接入点") : t("新建接入点")}</h3>
          <Button variant="ghost" size="sm" className="endpoint-icon-button" onClick={onClose} title={t("关闭")}>
            <X size={16} />
          </Button>
        </div>

        <form className="endpoint-form" onSubmit={onSubmit}>
          <div className="field-group endpoint-port-field">
            <label className="field-label" htmlFor="endpoint-port">
              {t("端口")}
            </label>
            <Input
              id="endpoint-port"
              type="number"
              inputMode="numeric"
              min={1}
              max={65535}
              required
              value={draft.port}
              onChange={(event) => onChange({ ...draft, port: event.target.value })}
            />
          </div>

          <div className="endpoint-form-section">
            <h4>{t("接入能力")}</h4>
            <label className="endpoint-switch-row" htmlFor="endpoint-management">
              <span>{t("允许登录管理页面")}</span>
              <Switch
                id="endpoint-management"
                checked={draft.allow_management}
                onChange={(event) => onChange({ ...draft, allow_management: event.target.checked })}
              />
            </label>
            <label className="endpoint-switch-row" htmlFor="endpoint-proxy">
              <span>{t("允许使用代理")}</span>
              <Switch id="endpoint-proxy" checked={draft.allow_proxy} onChange={(event) => setProxyEnabled(event.target.checked)} />
            </label>
          </div>

          {draft.allow_proxy ? (
            <div className="endpoint-form-section endpoint-protocol-section">
              <h4>{t("代理协议")}</h4>
              <label className="endpoint-switch-row" htmlFor="endpoint-http-forward">
                <span>{t("HTTP 正向代理")}</span>
                <Switch
                  id="endpoint-http-forward"
                  checked={draft.allow_http_forward}
                  onChange={(event) => setProtocol("allow_http_forward", event.target.checked)}
                />
              </label>
              <label className="endpoint-switch-row" htmlFor="endpoint-http-reverse">
                <span>{t("HTTP 反向代理")}</span>
                <Switch
                  id="endpoint-http-reverse"
                  checked={draft.allow_http_reverse}
                  onChange={(event) => setProtocol("allow_http_reverse", event.target.checked)}
                />
              </label>
              <label className="endpoint-switch-row" htmlFor="endpoint-socks5">
                <span>{t("SOCKS5 代理")}</span>
                <Switch
                  id="endpoint-socks5"
                  checked={draft.allow_socks5}
                  onChange={(event) => setProtocol("allow_socks5", event.target.checked)}
                />
              </label>
            </div>
          ) : null}

          {draft.allow_proxy && (draft.allow_http_forward || draft.allow_socks5) ? (
            <div className="endpoint-form-section">
              <h4>{t("代理认证")}</h4>
              <label className="endpoint-switch-row" htmlFor="endpoint-require-auth-info">
                <span>{t("当系统未设定代理令牌时，也强制客户端发送代理认证信息")}</span>
                <Switch
                  id="endpoint-require-auth-info"
                  checked={draft.require_proxy_auth_info}
                  onChange={(event) => onChange({ ...draft, require_proxy_auth_info: event.target.checked })}
                />
              </label>
            </div>
          ) : null}

          <div className="endpoint-form-actions">
            <Button variant="secondary" onClick={onClose} disabled={pending}>
              {t("取消")}
            </Button>
            <Button type="submit" disabled={pending}>
              {pending ? t("保存中...") : t("保存")}
            </Button>
          </div>
        </form>
      </Card>
    </div>
  );
}

export function EndpointPage() {
  const { t } = useI18n();
  const queryClient = useQueryClient();
  const { toasts, showToast, dismissToast } = useToast();
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingEndpoint, setEditingEndpoint] = useState<Endpoint | null>(null);
  const [draft, setDraft] = useState<EndpointDraft | null>(null);

  const endpointsQuery = useQuery({
    queryKey: ["endpoints"],
    queryFn: listEndpoints,
    refetchInterval: 10_000,
  });
  const envQuery = useQuery({
    queryKey: ["system-config-env", "endpoints"],
    queryFn: getEnvConfig,
    staleTime: 30_000,
  });
  const endpoints = endpointsQuery.data ?? EMPTY_ENDPOINTS;
  const proxyTokenSet = envQuery.data?.proxy_token_set ?? true;

  const invalidateEndpoints = async () => {
    await queryClient.invalidateQueries({ queryKey: ["endpoints"] });
  };

  const saveMutation = useMutation({
    mutationFn: async ({ endpoint, input }: { endpoint: Endpoint | null; input: EndpointInput }) => {
      return endpoint ? updateEndpoint(endpoint.id, input) : createEndpoint(input);
    },
    onSuccess: async (saved) => {
      await invalidateEndpoints();
      setEditorOpen(false);
      setEditingEndpoint(null);
      setDraft(null);
      showToast("success", t("接入点 {{port}} 已保存", { port: saved.port }));
    },
    onError: (error) => showToast("error", formatApiErrorMessage(error, t)),
  });

  const deleteMutation = useMutation({
    mutationFn: deleteEndpoint,
    onSuccess: async () => {
      await invalidateEndpoints();
      showToast("success", t("接入点已删除"));
    },
    onError: (error) => showToast("error", formatApiErrorMessage(error, t)),
  });

  const openCreate = () => {
    setEditingEndpoint(null);
    setDraft(newEndpointDraft(endpoints));
    setEditorOpen(true);
  };

  const openEdit = (endpoint: Endpoint) => {
    setEditingEndpoint(endpoint);
    setDraft(endpointToDraft(endpoint));
    setEditorOpen(true);
  };

  const closeEditor = () => {
    if (saveMutation.isPending) return;
    setEditorOpen(false);
    setEditingEndpoint(null);
    setDraft(null);
  };

  const submitEditor = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!draft) return;
    const port = Number(draft.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      showToast("error", t("端口必须是 1 到 65535 之间的整数"));
      return;
    }
    if (!draft.allow_management && !draft.allow_proxy) {
      showToast("error", t("管理页面和代理至少启用一项"));
      return;
    }
    if (draft.allow_proxy && !draft.allow_http_forward && !draft.allow_http_reverse && !draft.allow_socks5) {
      showToast("error", t("至少启用一种代理协议"));
      return;
    }
    saveMutation.mutate({ endpoint: editingEndpoint, input: { ...draft, port } });
  };

  const removeEndpoint = (endpoint: Endpoint) => {
    const confirmed = window.confirm(t("确认删除接入点 {{port}}？", { port: endpoint.port }));
    if (confirmed) deleteMutation.mutate(endpoint.id);
  };

  return (
    <section className="endpoint-page">
      <header className="module-header endpoint-page-header">
        <div>
          <h2>{t("接入点")}</h2>
          <p className="module-description">{t("管理 Resin 对外监听的端口与可用能力。")}</p>
        </div>
        <div className="endpoint-page-actions">
          <Button variant="secondary" size="sm" onClick={() => void endpointsQuery.refetch()} disabled={endpointsQuery.isFetching}>
            <RefreshCw size={16} className={endpointsQuery.isFetching ? "spin" : undefined} />
            {t("刷新")}
          </Button>
          <Button size="sm" onClick={openCreate}>
            <Plus size={16} />
            {t("新建接入点")}
          </Button>
        </div>
      </header>

      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {endpointsQuery.isLoading ? <p className="endpoint-loading">{t("正在加载接入点...")}</p> : null}
      {endpointsQuery.isError ? (
        <div className="callout callout-error">
          <AlertTriangle size={16} />
          <span>{formatApiErrorMessage(endpointsQuery.error, t)}</span>
        </div>
      ) : null}

      <div className="endpoint-list">
        {endpoints.map((endpoint) => {
          const status = statusPresentation(endpoint.status);
          const capabilities = enabledCapabilities(endpoint);
          const authLabel = proxyTokenSet
            ? "Proxy Token 认证"
            : endpoint.require_proxy_auth_info
              ? "当系统未设定代理令牌时，也强制客户端发送代理认证信息"
              : "代理免认证";

          return (
            <Card className="endpoint-card" key={endpoint.id}>
              <div className="endpoint-card-head">
                <div className="endpoint-card-title">
                  <span className={`endpoint-status-dot ${status.className}`} aria-hidden="true" />
                  <h3>{endpoint.port}</h3>
                  <span>{endpoint.read_only ? t("默认接入点") : t("自定义接入点")}</span>
                </div>
                <div className="endpoint-card-controls">
                  <span className={`endpoint-status ${status.className}`}>{t(status.label)}</span>
                  {endpoint.read_only ? (
                    <span className="endpoint-readonly" title={t("默认接入点由环境变量定义，只读且不可删除")}>
                      <LockKeyhole size={15} />
                    </span>
                  ) : (
                    <>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="endpoint-icon-button"
                        onClick={() => openEdit(endpoint)}
                        title={t("编辑接入点 {{port}}", { port: endpoint.port })}
                        aria-label={t("编辑接入点 {{port}}", { port: endpoint.port })}
                      >
                        <Pencil size={15} />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="endpoint-icon-button endpoint-delete-button"
                        onClick={() => removeEndpoint(endpoint)}
                        disabled={deleteMutation.isPending}
                        title={t("删除接入点 {{port}}", { port: endpoint.port })}
                        aria-label={t("删除接入点 {{port}}", { port: endpoint.port })}
                      >
                        <Trash2 size={15} />
                      </Button>
                    </>
                  )}
                </div>
              </div>

              <div className="endpoint-capabilities" aria-label={t("已启用能力")}>
                {capabilities.map((capability) => (
                  <span key={capability}>
                    <Check size={14} aria-hidden="true" />
                    {t(capability)}
                  </span>
                ))}
              </div>

              {endpoint.allow_proxy ? <p className="endpoint-auth-policy">{t(authLabel)}</p> : null}

              {endpoint.last_error ? (
                <div className="endpoint-error" role="status">
                  <AlertTriangle size={14} />
                  <span>{endpoint.last_error}</span>
                </div>
              ) : null}
            </Card>
          );
        })}
      </div>

      {editorOpen && draft ? (
        <EndpointEditor
          endpoint={editingEndpoint}
          draft={draft}
          pending={saveMutation.isPending}
          onChange={setDraft}
          onClose={closeEditor}
          onSubmit={submitEditor}
        />
      ) : null}
    </section>
  );
}
