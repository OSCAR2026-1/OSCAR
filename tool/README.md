# OSCAR

OSCAR analyzes the runtime effects of known open-source vulnerabilities in
MCP-based agent systems. It connects vulnerability localization, effect
inference, runtime evidence, and cross-layer propagation to determine what a
vulnerability produced and how far that effect reached during execution.

## Overview

Traditional reachability analysis determines whether vulnerable code can
execute. OSCAR additionally identifies the resulting vulnerability-derived
effect and follows it across the MCP server, Tool result, Agent Host, session,
and model-visible observation.

```text
Known OSS Vulnerability
  -> Vulnerability Localization
  -> Effect Inference
  -> Cross-Layer Propagation Graph
  -> Runtime Impact Assessment
```

OSCAR models three effect types:

- `CONTROL_EFFECT`: control-flow, authorization, or execution changes;
- `RESOURCE_EFFECT`: changes to files, processes, network resources, or state;
- `VALUE_EFFECT`: vulnerability-derived values, sensitive data, or outputs.

For each realized effect, OSCAR reports its maximum propagation boundary:

- `B_ENV`: the effect remains in the runtime environment;
- `B_TOOL`: the effect reaches the Tool-facing layers;
- `B_AGENT`: the effect reaches the model-visible Agent observation.

## Method

OSCAR consists of four analysis stages:

1. **Vulnerability localization** identifies patch-linked anchors and repair
   predicates from advisory metadata and vulnerable/fixed source pairs.
2. **Effect inference** constructs effect instances with conditions, carriers,
   sinks, and provenance.
3. **Cross-layer graph construction** connects static program structure with
   runtime evidence from the server through L0-L4 Agent layers.
4. **Runtime impact assessment** determines effect realization, attribution,
   and the maximum observed propagation boundary.

The implementation supports vulnerabilities in an MCP server, a direct runtime
dependency, or an MCP framework.

## Installation

OSCAR requires Python 3.11 or later.

```bash
git clone https://github.com/OSCAR2026-1/OSCAR.git
cd OSCAR
python3 -m pip install -e .
```

The main dependencies are `jsonschema` and `PyYAML`.

## Quick Start

Run OSCAR on a prepared case:

```bash
oscar run-blind \
  --case path/to/blind_case.json \
  --output /tmp/oscar-run
```

The same command can be executed directly from the source tree:

```bash
PYTHONPATH=. python3 oscar.py run-blind \
  --case path/to/blind_case.json \
  --output /tmp/oscar-run
```

Run a benchmark manifest:

```bash
PYTHONPATH=. python3 oscar.py run-test-set \
  --manifest path/to/test_set.json \
  --output /tmp/oscar-benchmark-run \
  --workers 4
```

## Outputs

Each case produces a structured analysis directory:

| Artifact | Description |
| --- | --- |
| `localization.json` | Vulnerability anchors and repair predicates |
| `effect_model.json` | Effect instances, carriers, sinks, and provenance |
| `cross_layer_graph.json` | Full attributed propagation graph |
| `cross_layer_graph_view.json` | Effect-centered graph projection |
| `graph_validation.json` | Graph and continuous-path validation |
| `prediction.json` | Runtime impact and propagation-boundary prediction |
| `diagnostic.json` | Structured execution diagnostics |

The main prediction fields are `predicted_impact`, `impact_effect_ids`,
`maximum_effect_boundary`, `predicted_boundary_class`, `agent_visible`, and
`per_effect`.

## Benchmark

The evaluation dataset and reproducibility materials are maintained in the
[OSCAR-Benchmark](https://github.com/OSCAR2026-1/OSCAR-Benchmark) repository.
Its manifest can be passed directly to `run-test-set`.

## Repository Structure

```text
oscar/analysis/      localization, effect modeling, graph, and impact analysis
oscar/contracts/     component and prediction contracts
oscar/runtime/       execution, environment, and Host integration
oscar/workflows/     onboarding, assembly, and experiment workflows
oscar/evaluation/    evaluation utilities
oscar/schemas/       versioned JSON schemas
examples/            example effect-model artifacts
tests/               unit and integration tests
```

## Tests

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
python3 scripts/build_public_release.py --verify-only
```

## Citation

Citation information will be added upon publication.

## License

OSCAR is released under the [Apache License 2.0](LICENSE).
