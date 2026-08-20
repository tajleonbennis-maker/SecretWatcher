from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProductAdapter:
    """Conservative public configuration routes for one recognized product."""

    product: str
    aliases: tuple[str, ...]
    public_paths: tuple[str, ...]
    maturity: str
    evidence: str


ADAPTERS = (
    ProductAdapter(
        product="DeepTutor",
        aliases=("deeptutor",),
        public_paths=("/api/v1/settings", "/api/v1/settings/llm-options"),
        maturity="verified",
        evidence="上游源码审计与真实公网样本验证",
    ),
    ProductAdapter(
        product="Dify",
        aliases=("dify",),
        public_paths=("/console/api/setup",),
        maturity="seed",
        evidence="公开初始化接口种子，等待更多真实样本校准",
    ),
    ProductAdapter(
        product="Open WebUI",
        aliases=("open webui", "open-webui", "open_webui"),
        public_paths=("/api/config",),
        maturity="seed",
        evidence="公开运行配置接口种子，等待更多真实样本校准",
    ),
    ProductAdapter(
        product="AnythingLLM",
        aliases=("anythingllm",),
        public_paths=("/api/system",),
        maturity="seed",
        evidence="产品公开系统信息接口种子",
    ),
    ProductAdapter(
        product="LibreChat",
        aliases=("librechat",),
        public_paths=("/api/config",),
        maturity="seed",
        evidence="产品公开运行配置接口种子",
    ),
    ProductAdapter("LobeChat", ("lobechat", "lobe chat"), (), "planned", "等待源码审计"),
    ProductAdapter("FastGPT", ("fastgpt",), (), "planned", "等待源码审计"),
    ProductAdapter("RAGFlow", ("ragflow",), (), "planned", "等待源码审计"),
    ProductAdapter("LiteLLM Proxy", ("litellm proxy", "litellm"), (), "planned", "等待源码审计"),
    ProductAdapter("New API", ("new api", "new-api"), (), "planned", "等待源码审计"),
    ProductAdapter("One API", ("one api", "one-api"), (), "planned", "等待源码审计"),
    ProductAdapter("ChatGPT-Next-Web", ("chatgpt-next-web", "nextchat"), (), "planned", "等待源码审计"),
)


_BY_ALIAS = {
    alias.casefold(): adapter
    for adapter in ADAPTERS
    for alias in (adapter.product, *adapter.aliases)
}


def adapter_for(product: str) -> ProductAdapter | None:
    return _BY_ALIAS.get(product.strip().casefold())


def public_paths_for(product: str) -> tuple[str, ...]:
    adapter = adapter_for(product)
    return adapter.public_paths if adapter else ()


def public_adapter_summary() -> list[dict[str, object]]:
    return [
        {
            "product": adapter.product,
            "maturity": adapter.maturity,
            "active_paths": len(adapter.public_paths),
        }
        for adapter in ADAPTERS
    ]
