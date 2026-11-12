"""Make AgentDojo's Gemini adapter work with Gemini 3 models.

Gemini 3 attaches an opaque "thought signature" to each function call and
rejects the next request unless the model's turn is sent back with it.
AgentDojo 0.1.35 rebuilds the model's turn from its own message format and
drops the signature, so every multi-step task fails with a 400.

The fix keeps the model's original turn next to AgentDojo's copy and sends
that original back unchanged. Nothing about the task, the tools, the attack
or the scoring is altered.
"""

from __future__ import annotations

from agentdojo.agent_pipeline.llms import google_llm

_KEY = "_google_original_content"
_applied = False


def apply() -> None:
    global _applied
    if _applied:
        return
    _applied = True

    to_assistant = google_llm._google_to_assistant_message
    to_google = google_llm._message_to_google

    def keep_original(response):
        message = to_assistant(response)
        if response.candidates and response.candidates[0].content is not None:
            message[_KEY] = response.candidates[0].content  # type: ignore[typeddict-unknown-key]
        return message

    def send_original(message):
        if message["role"] == "assistant" and message.get(_KEY) is not None:
            return message[_KEY]
        return to_google(message)

    google_llm._google_to_assistant_message = keep_original
    google_llm._message_to_google = send_original
