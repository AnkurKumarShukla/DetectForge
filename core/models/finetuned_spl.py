"""Fine-tuned SPL generator — Together AI inference on a PEFT/LoRA fine-tuned model.

Workflow:
  1. Run scripts/prepare_finetune_data.py → spl_finetune.jsonl
  2. Upload to Together AI:  together fine-tuning upload spl_finetune.jsonl
  3. Start a fine-tuning job (Foundation-sec-1.1-8b or Llama-3.1-8b base):
       together fine-tuning create --training-file <file-id> --model togethercomputer/Llama-3.1-8b
  4. Set .env:  FINETUNED_MODEL_ID=<your-account>/<job-id>  USE_FINETUNED_SPL=true
  5. DetectForge picks it up on next restart — no code changes needed.

Cost estimate: ~$3-5 for an 8b model on a few hundred SPL examples.
"""
import logging

from openai import OpenAI

from core.config import get_settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a Splunk detection engineer. "
    "Given a MITRE ATT&CK technique and environment context, write a Splunk SPL detection rule. "
    "Return only valid SPL — no explanation, no markdown fences, no comments."
)


class FinetunedSPLGenerator:
    """Calls a Together AI fine-tuned model for SPL generation.

    Drop-in replacement for mcp.generate_spl(). Activated when
    USE_FINETUNED_SPL=true and FINETUNED_MODEL_ID is set in .env.
    """

    def __init__(self):
        settings = get_settings()
        self._client = OpenAI(
            api_key=settings.together_api_key,
            base_url="https://api.together.xyz/v1",
        )
        self._model = settings.finetuned_model_id
        logger.info("FinetunedSPLGenerator loaded — model: %s", self._model)

    def generate_spl(self, prompt: str, additional_context: str = "") -> str:
        """Generate SPL using the fine-tuned model. Same signature as mcp.generate_spl()."""
        user = f"{prompt}\n\nContext: {additional_context}" if additional_context else prompt
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user[:3000]},
            ],
            max_tokens=512,
            temperature=0.1,
        )
        content = resp.choices[0].message.content or ""
        # Strip any accidental markdown fences the model might still emit
        for fence in ("```splunk", "```spl", "```"):
            content = content.replace(fence, "")
        return content.strip()
