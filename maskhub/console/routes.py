"""Route table wiring the handlers to the runtime."""

from __future__ import annotations

from functools import partial

from maskhub.console.handlers import audit, catalog, consumer, policy, precheck, rule, source, system
from maskhub.console.http import Request, Response
from maskhub.console.router import Router


def build_router(runtime) -> Router:
    router = Router()
    bind = partial

    router.get("/health", bind(system.health, runtime))
    router.get("/status", bind(system.status, runtime))

    router.get("/sources", bind(source.list_sources, runtime))
    router.post("/sources", bind(source.register_source, runtime))
    router.post("/source/status", bind(source.set_source_status, runtime))

    router.get("/datasets", bind(catalog.list_datasets, runtime))
    router.post("/datasets", bind(catalog.register_dataset, runtime))
    router.get("/dataset", bind(catalog.get_dataset, runtime))

    router.get("/rules", bind(rule.list_rules, runtime))
    router.post("/rules", bind(rule.create_rule, runtime))
    router.post("/rule/remove", bind(rule.remove_rule, runtime))
    router.post("/rule/match", bind(rule.match_rule, runtime))

    router.get("/policies", bind(policy.list_policies, runtime))
    router.post("/policies", bind(policy.create_policy, runtime))
    router.post("/policy/activate", bind(policy.activate_policy, runtime))
    router.post("/policy/retire", bind(policy.retire_policy, runtime))
    router.post("/policy/coverage", bind(policy.policy_coverage, runtime))
    router.get("/policy/gaps", bind(policy.coverage_gap, runtime))

    router.get("/consumers", bind(consumer.list_consumers, runtime))
    router.post("/consumers", bind(consumer.register_consumer, runtime))
    router.get("/consumer", bind(consumer.get_consumer, runtime))

    router.post("/precheck", bind(precheck.run_precheck, runtime))
    router.get("/prechecks", bind(precheck.list_prechecks, runtime))
    router.get("/precheck", bind(precheck.get_precheck, runtime))
    router.post("/precheck/verify", bind(precheck.verify_precheck, runtime))

    router.get("/audit", bind(audit.list_audit, runtime))
    router.get("/audit/summary", bind(audit.audit_summary, runtime))
    router.get("/audit/latest", bind(audit.audit_latest, runtime))
    router.get("/audit/action", bind(audit.audit_by_action, runtime))

    def route_table(request: Request) -> Response:
        return Response.json(200, {"count": len(router), "routes": router.describe()})

    router.get("/routes", route_table)
    return router
