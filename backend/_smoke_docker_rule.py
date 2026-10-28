"""Docker compromise requires a connected execution/authority witness."""
import copy
import unittest

import yaml

import main as m


CHECKOUT = {"uses": "actions/checkout@v4", "with": {"ref": "${{ github.event.pull_request.head.sha }}"}}
GATEWAY = {"run": "docker run -d -v /var/run/docker.sock:/var/run/docker.sock trusted-gateway:1"}
PERMISSION_HELPER = """module.exports = async ({ github, context, core }) => {
const { data } = await github.rest.repos.getCollaboratorPermissionLevel({
owner: context.repo.owner, repo: context.repo.repo, username: context.actor });
if (!['admin', 'maintain', 'write'].includes(data.permission)) { throw new Error('denied'); }
};
"""
HELPER_STEP = {
    "uses": "actions/github-script@v7",
    "with": {"script": "await require('./.github/check-permission.cjs')({github, context, core});"},
}


class DockerFlowTests(unittest.TestCase):
    def scan(self, steps, trigger="issue_comment", job_extra=None, other_jobs=None, support=None, repo="acme/demo"):
        job = {"runs-on": "ubuntu-latest", "permissions": {"contents": "write"}, "steps": steps}
        job.update(job_extra or {})
        document = {"name": "docker-test", "on": trigger, "jobs": {**(other_jobs or {}), "test": job}}
        text = yaml.safe_dump(document, sort_keys=False, width=2000)
        findings = m.analyze_workflow(repo, f"https://github.com/{repo}", ".github/workflows/test.yml", text, support_files=support)
        return [finding for finding in findings if finding.category == "docker-runner-compromise"]

    def test_fixed_setup_is_not_an_attack_path(self):
        for script in (
            "set -eo pipefail\ndocker pull trusted:1",
            "docker run --privileged trusted:1",
            "docker run --network host trusted:1",
            "docker login ghcr.io",
            "docker build .",
            "echo 'docker run --privileged attacker'",
        ):
            with self.subTest(script=script):
                self.assertEqual(self.scan([{"run": script}]), [])

    def test_gateway_socket_is_not_the_isolated_agents_socket(self):
        steps = [
            GATEWAY,
            {"run": 'docker run --rm --network host -e BODY="$BODY" isolated-agent:1 --allow-all-tools',
             "env": {"BODY": "${{ github.event.comment.body }}"}},
        ]
        self.assertEqual(self.scan(steps), [])

    def test_socket_gateway_receiving_data_is_not_attacker_execution(self):
        step = {"run": 'docker run -v /var/run/docker.sock:/var/run/docker.sock -e BODY="$BODY" trusted-gateway:1',
                "env": {"BODY": "${{ github.event.comment.body }}"}}
        self.assertEqual(self.scan([step]), [])

    def test_prompt_in_quoted_heredoc_is_not_shell_execution(self):
        script = "cat <<'PROMPT' > prompt.txt\nUse BODY as context\nPROMPT\ncopilot --prompt-file prompt.txt --allow-all-tools"
        self.assertEqual(self.scan([GATEWAY, {"run": script, "env": {"BODY": "${{ github.event.comment.body }}"}}]), [])

    def test_raw_github_interpolation_is_not_made_safe_by_a_heredoc(self):
        script = "cat <<'PROMPT' > prompt.txt\n${{ github.event.comment.body }}\nPROMPT"
        self.assertEqual(len(self.scan([GATEWAY, {"run": script}])), 1)

    def test_checkout_without_execution_and_ordinary_builds(self):
        for final in (
            {"run": "cat README.md"},
            {"run": "docker build ."},
            {"uses": "docker/build-push-action@v6", "with": {"context": "."}},
        ):
            self.assertEqual(self.scan([CHECKOUT, GATEWAY, final], "pull_request_target"), [])

    def test_host_pr_script_and_daemon_form_a_witness(self):
        findings = self.scan([CHECKOUT, GATEWAY, {"run": "bash ./scripts/test.sh"}], "pull_request_target")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity, "MEDIUM")
        self.assertEqual(finding.exploitability, "CONDITIONAL")
        self.assertGreaterEqual(finding.confidence, 80)
        self.assertIsNotNone(finding.line_number)
        self.assertIn("docker run", finding.detected_sink_line)
        self.assertTrue(any("execution-context: runner-host" in line for line in finding.evidence))
        for prefix in ("source:", "execution:", "sink:", "flow:", "workflow-sha256:", "revision:", "impact assumptions:"):
            self.assertTrue(any(line.startswith(prefix) for line in finding.evidence), prefix)
        self.assertEqual(m._compute_cvss(finding), (None, None))

    def test_pr_local_action_is_execution_but_not_checkout_alone(self):
        self.assertEqual(len(self.scan([CHECKOUT, GATEWAY, {"uses": "./.github/actions/test"}], "pull_request_target")), 1)

    def test_direct_shell_injection_has_a_witness(self):
        findings = self.scan([GATEWAY, {"run": 'echo "${{ github.event.comment.body }}"'}])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].tainted_expression, "github.event.comment.body")
        self.assertEqual(self.scan([GATEWAY, {"run": 'echo "${{ github.event.issue.body }}"'}], "pull_request"), [])

    def test_attacker_selected_image_only_with_explicit_host_authority(self):
        env = {"IMAGE": "${{ github.event.comment.body }}"}
        for mount in ("-v /var/run/docker.sock:/var/run/docker.sock", "-v /:/host"):
            findings = self.scan([{"run": f'docker run {mount} "$IMAGE"', "env": env}])
            self.assertEqual(len(findings), 1)
            self.assertIn("docker-container", " ".join(findings[0].evidence))
        for flags in ("", "--network host", "--privileged"):
            self.assertEqual(self.scan([{"run": f'docker run {flags} "$IMAGE"', "env": env}]), [])
        self.assertEqual(self.scan([{
            "run": 'docker run -v /:/host "$IMAGE"',
            "env": {"IMAGE": "trusted:${{ github.event.comment.body }}"},
        }]), [])

    def test_data_is_interpreted_only_by_an_explicit_container_shell(self):
        env = {"BODY": "${{ github.event.comment.body }}"}
        self.assertEqual(len(self.scan([{
            "run": 'docker run -v /:/host alpine sh -c "$BODY"', "env": env,
        }])), 1)
        self.assertEqual(self.scan([{
            "run": 'docker run -v /:/host agent copilot --prompt "$BODY" --allow-all-tools', "env": env,
        }]), [])
        self.assertEqual(self.scan([{
            "run": 'docker run --network host alpine sh -c "$BODY"', "env": env,
        }]), [])
        self.assertEqual(len(self.scan([{
            "run": 'docker run -v /:/host --entrypoint sh alpine -c "$BODY"', "env": env,
        }])), 1)

    def test_labels_and_unknown_options_are_not_mistaken_for_an_image(self):
        env = {"BODY": "${{ github.event.comment.body }}"}
        for flag in ("--label", "--future-option"):
            self.assertEqual(self.scan([{
                "run": f'docker run -v /:/host {flag} "$BODY" alpine', "env": env,
            }]), [])

    def test_job_environment_source_is_located_in_its_own_job(self):
        steps = [GATEWAY, {"run": 'eval "$BODY"'}]
        findings = self.scan(steps, job_extra={"env": {"BODY": "${{ github.event.comment.body }}"}})
        self.assertEqual(len(findings), 1)
        self.assertTrue(any(line.startswith("source: .github/workflows/test.yml:") for line in findings[0].evidence))

    def test_multiple_triggers_preserve_the_admitted_comment_path(self):
        steps = [GATEWAY, {"run": 'echo "${{ github.event.comment.body }}"'}]
        findings = self.scan(
            steps, trigger=["issues", "issue_comment"],
            job_extra={"if": "github.event.issue.author_association == 'MEMBER'"},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].trigger, "issue_comment")

    def test_daemonless_commands_do_not_prove_socket_authority(self):
        for command in ("docker login ghcr.io", "docker compose config", "docker buildx version"):
            self.assertEqual(self.scan([{"run": command}, {"run": 'echo "${{ github.event.comment.body }}"'}]), [])

    def test_environment_data_requires_interpretation(self):
        env = {"TEXT": "${{ github.event.comment.body }}"}
        self.assertEqual(self.scan([GATEWAY, {"run": 'printf "%s" "$TEXT"', "env": env}]), [])
        self.assertEqual(len(self.scan([GATEWAY, {"run": 'eval "$TEXT"', "env": env}])), 1)

    def test_multiline_docker_operation_keeps_real_locations(self):
        findings = self.scan([{
            "run": 'docker run \\\n  -v /:/host \\\n  "$IMAGE"',
            "env": {"IMAGE": "${{ github.event.comment.body }}"},
        }])
        self.assertEqual(len(findings), 1)
        self.assertIsNotNone(findings[0].line_number)

    def test_container_context_does_not_inherit_host_gateway(self):
        extra = {"container": {"image": "isolated:1"}}
        self.assertEqual(self.scan([GATEWAY, {"run": 'eval "$TEXT"', "env": {"TEXT": "${{ github.event.comment.body }}"}}], job_extra=extra), [])
        extra["container"]["volumes"] = ["/var/run/docker.sock:/var/run/docker.sock"]
        self.assertEqual(len(self.scan([GATEWAY, {"run": 'eval "$TEXT"', "env": {"TEXT": "${{ github.event.comment.body }}"}}], job_extra=extra)), 1)

    def test_remote_daemon_is_not_local_runner_authority(self):
        steps = [GATEWAY, {"run": 'echo "${{ github.event.comment.body }}"'}]
        self.assertEqual(self.scan(steps, job_extra={"env": {"DOCKER_HOST": "tcp://remote:2376"}}), [])

    def test_checked_out_code_replaced_by_trusted_checkout(self):
        trusted = {"uses": "actions/checkout@v4", "with": {"ref": "main"}}
        self.assertEqual(self.scan([CHECKOUT, trusted, GATEWAY, {"run": "npm ci"}], "pull_request_target"), [])

    def test_role_gate_and_or_bypass(self):
        steps = [GATEWAY, {"run": 'echo "${{ github.event.comment.body }}"'}]
        role = "github.event.comment.author_association == 'MEMBER'"
        self.assertEqual(self.scan(steps, job_extra={"if": role}), [])
        self.assertEqual(len(self.scan(steps, job_extra={"if": role + " || true"})), 1)
        # Authorizing the issue author does not authorize a later commenter.
        self.assertEqual(len(self.scan(steps, job_extra={"if": "github.event.issue.author_association == 'MEMBER'"})), 1)

    def test_permission_helper_and_dependency_order(self):
        steps = [GATEWAY, {"run": 'echo "${{ github.event.comment.body }}"'}]
        pre = {"runs-on": "ubuntu-latest", "steps": [HELPER_STEP]}
        support = {".github/check-permission.cjs": PERMISSION_HELPER}
        self.assertEqual(self.scan(steps, job_extra={"needs": "pre"}, other_jobs={"pre": pre}, support=support), [])
        self.assertEqual(len(self.scan(steps, job_extra={"needs": "pre", "if": "always()"}, other_jobs={"pre": pre}, support=support)), 1)
        self.assertEqual(len(self.scan(steps, job_extra={"needs": "pre", "if": "needs.pre.outputs.activated == 'true'"}, other_jobs={"pre": pre})), 1)
        self.assertEqual(self.scan([HELPER_STEP, *steps], support=support), [])
        self.assertEqual(len(self.scan([*steps, HELPER_STEP], support=support)), 1)

    def test_non_fail_closed_or_swallowed_helpers_do_not_exonerate(self):
        for helper in (
            PERMISSION_HELPER.replace("throw new Error('denied');", "console.log('denied');"),
            PERMISSION_HELPER.replace("context.actor", "context.payload.issue.user.login"),
        ):
            self.assertEqual(len(self.scan(
                [HELPER_STEP, GATEWAY, {"run": 'echo "${{ github.event.comment.body }}"'}],
                support={".github/check-permission.cjs": helper},
            )), 1)
        step = copy.deepcopy(HELPER_STEP)
        step["continue-on-error"] = True
        self.assertEqual(len(self.scan(
            [step, GATEWAY, {"run": 'echo "${{ github.event.comment.body }}"'}],
            support={".github/check-permission.cjs": PERMISSION_HELPER},
        )), 1)

    def test_approval_and_unknown_outputs_are_conditional_not_critical(self):
        steps = [GATEWAY, {"run": 'echo "${{ github.event.comment.body }}"'}]
        for extra in ({"environment": "review"}, {"if": "needs.activation.outputs.allowed == 'true'"}):
            finding = self.scan(steps, job_extra=extra)[0]
            self.assertEqual((finding.severity, finding.exploitability), ("MEDIUM", "CONDITIONAL"))
            self.assertTrue(any("gate-evaluation: unknown" == line for line in finding.evidence))
            self.assertEqual(m._compute_cvss(finding), (None, None))

    def test_reports_and_sarif_do_not_invent_a_score_or_escape(self):
        finding = self.scan([GATEWAY, {"run": 'echo "${{ github.event.comment.body }}"'}])[0]
        report = m.build_bug_bounty_report(finding)
        self.assertIsNone(report.cvss_score)
        self.assertIsNone(report.cvss_vector)
        self.assertIn("Not scored", report.markdown)
        self.assertIn("not proof of host escape", report.proof_of_concept)
        self.assertNotIn("security-severity", m._sarif_result(finding)["properties"])
        self.assertIn("unscored", m._sarif_result(finding)["properties"]["cvss-status"])

    def test_same_template_retains_repository_identity(self):
        steps = [GATEWAY, {"run": 'echo "${{ github.event.comment.body }}"'}]
        first = self.scan(steps, repo="acme/one")[0]
        second = self.scan(steps, repo="acme/two")[0]
        self.assertNotEqual(first.id, second.id)


if __name__ == "__main__":
    unittest.main()
