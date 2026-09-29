"""
Open WebUI global Filter.
Проверяет:
1) пользовательский ввод в inlet();
2) полный payload в request() — включая RAG/tool context прямо перед провайдером.

В Admin Panel -> Functions создайте новый Function, вставьте этот код,
включите Active + Global.

Требует Open WebUI, где поддерживается request() filter hook (v0.11.2+).
"""

from typing import Optional
import httpx
from pydantic import BaseModel, Field


class Filter:
    class Valves(BaseModel):
        SECURITY_GATEWAY_URL: str = Field(
            default="http://security-gateway:8080",
            description="URL OSS security gateway",
        )
        FAIL_CLOSED: bool = True

    def __init__(self):
        self.valves = self.Valves()

    @staticmethod
    def _content_to_text(content) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            out = []
            for part in content:
                if isinstance(part, dict):
                    if isinstance(part.get("text"), str):
                        out.append(part["text"])
                    elif part.get("type") == "text" and isinstance(part.get("content"), str):
                        out.append(part["content"])
            return "\n".join(out)
        return ""

    @classmethod
    def _messages_to_text(cls, messages: list[dict]) -> str:
        chunks = []
        for m in messages or []:
            role = m.get("role", "unknown")
            text = cls._content_to_text(m.get("content"))
            if text:
                chunks.append(f"[{role}]\n{text}")
        return "\n\n".join(chunks)

    async def _scan(self, text: str, source: str) -> dict:
        if not text.strip():
            return {"action": "ALLOW", "categories": [], "findings": []}

        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                f"{self.valves.SECURITY_GATEWAY_URL.rstrip('/')}/v1/scan/text",
                json={"text": text, "source": source},
            )
            r.raise_for_status()
            return r.json()

    async def _notify(self, emitter, result: dict):
        if not emitter:
            return
        categories = ", ".join(result.get("categories", [])) or "SECURITY_POLICY"
        await emitter({
            "type": "status",
            "data": {
                "description": (
                    "Запрос заблокирован политикой ИБ. "
                    f"Категории: {categories}. "
                    "Удалите или обезличьте защищённую информацию."
                ),
                "done": True,
                "hidden": False,
            },
        })

    async def inlet(
        self,
        body: dict,
        __event_emitter__=None,
        __user__: Optional[dict] = None,
        **kwargs,
    ) -> dict:
        # Один раз на пользовательский turn: проверяем именно ввод пользователя.
        user_messages = [
            m for m in body.get("messages", [])
            if m.get("role") == "user"
        ]
        text = self._content_to_text(user_messages[-1].get("content")) if user_messages else ""

        try:
            result = await self._scan(text, "openwebui:inlet")
        except Exception:
            if self.valves.FAIL_CLOSED:
                raise Exception("Security gateway недоступен. Запрос заблокирован (fail-closed).")
            return body

        if result.get("action") == "BLOCK":
            await self._notify(__event_emitter__, result)
            cats = ", ".join(result.get("categories", []))
            raise Exception(
                f"Передача запрещена политикой информационной безопасности. Категории: {cats}"
            )
        return body

    async def request(
        self,
        body: dict,
        __event_emitter__=None,
        __user__: Optional[dict] = None,
        **kwargs,
    ) -> dict:
        # Финальная граница: здесь уже присутствуют RAG chunks и tool context.
        text = self._messages_to_text(body.get("messages", []))

        try:
            result = await self._scan(text, "openwebui:request")
        except Exception:
            if self.valves.FAIL_CLOSED:
                raise Exception("Security gateway недоступен. Запрос заблокирован (fail-closed).")
            return body

        if result.get("action") == "BLOCK":
            await self._notify(__event_emitter__, result)
            cats = ", ".join(result.get("categories", []))
            raise Exception(
                f"Передача запрещена политикой информационной безопасности. Категории: {cats}"
            )
        return body
