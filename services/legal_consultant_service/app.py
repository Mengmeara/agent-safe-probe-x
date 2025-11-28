from __future__ import annotations

from flask import Flask, jsonify, request

from .runner import LegalConsultantService, LegalConsultantServiceError


service = LegalConsultantService()
app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "agent": service.config.agent_path})


@app.route("/run", methods=["POST"])
def run_agent():
    payload = request.get_json(force=True, silent=True) or {}
    task = payload.get("task")
    attacker_tool = payload.get("attacker_tool")
    workflow_mode = payload.get("workflow_mode")
    attack_mode = payload.get("attack_mode", "none")

    try:
        result = service.run_task(
            task,
            attacker_tool=attacker_tool,
            workflow_mode=workflow_mode,
            attack_mode=attack_mode,
        )
    except LegalConsultantServiceError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:  # pragma: no cover - defensive
        return jsonify({"error": f"Internal error: {exc}"}), 500

    return jsonify(result)


def main():
    app.run(host="0.0.0.0", port=5055, debug=False)


if __name__ == "__main__":
    main()

