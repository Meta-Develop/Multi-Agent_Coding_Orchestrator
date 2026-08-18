// Client-side objective-profile preview. The GUI does not persist or decide;
// it re-scores recorded evaluation documents under operator-proposed weights.

export const DEFAULT_OBJECTIVE = {
  id: "maco-default-v1",
  version: 1,
  label: "MACO default (50/25/25 quality)",
  quality: {
    held_out: 50,
    breadth: 25,
    anti_shortcut: 25,
  },
  axes: {
    quality: 100,
    cost: 0,
    latency: 0,
    rework: 0,
  },
};

export function cloneObjective(profile) {
  const source = profile && typeof profile === "object" ? profile : DEFAULT_OBJECTIVE;
  return {
    id: String(source.id || DEFAULT_OBJECTIVE.id),
    version: Number(source.version) || 1,
    label: String(source.label || source.id || DEFAULT_OBJECTIVE.label),
    quality: {
      held_out: clampWeight(source.quality && source.quality.held_out, 50),
      breadth: clampWeight(source.quality && source.quality.breadth, 25),
      anti_shortcut: clampWeight(source.quality && source.quality.anti_shortcut, 25),
    },
    axes: {
      quality: clampWeight(source.axes && source.axes.quality, 100),
      cost: clampWeight(source.axes && source.axes.cost, 0),
      latency: clampWeight(source.axes && source.axes.latency, 0),
      rework: clampWeight(source.axes && source.axes.rework, 0),
    },
  };
}

export function qualityWeightSum(profile) {
  const quality = (profile && profile.quality) || {};
  return (
    Number(quality.held_out || 0) +
    Number(quality.breadth || 0) +
    Number(quality.anti_shortcut || 0)
  );
}

export function axisWeightSum(profile) {
  const axes = (profile && profile.axes) || {};
  return (
    Number(axes.quality || 0) +
    Number(axes.cost || 0) +
    Number(axes.latency || 0) +
    Number(axes.rework || 0)
  );
}

export function validateObjective(profile) {
  const errors = [];
  if (!profile || typeof profile !== "object") {
    return ["objective profile is missing"];
  }
  if (!profile.id) errors.push("profile id is required");
  const qualitySum = qualityWeightSum(profile);
  if (qualitySum !== 100) {
    errors.push("quality weights must sum to 100 (held-out + breadth + anti-shortcut)");
  }
  const axisSum = axisWeightSum(profile);
  if (axisSum <= 0) {
    errors.push("at least one selection axis must be positive");
  }
  return errors;
}

export function meanValue(precise) {
  if (!precise || typeof precise !== "object") return 0;
  const count = Number(precise.count) || 0;
  if (count === 0) return 0;
  return Number(precise.total || 0) / count;
}

export function rescoreQualityComponents(components, qualityWeights) {
  const held = Number(components.held_out_basis_points) || 0;
  const breadth = Number(components.breadth_basis_points) || 0;
  const anti = Number(components.anti_shortcut_basis_points) || 0;
  const weighted =
    held * Number(qualityWeights.held_out) +
    breadth * Number(qualityWeights.breadth) +
    anti * Number(qualityWeights.anti_shortcut);
  return Math.trunc(weighted / 100);
}

export function extractRunQuality(run) {
  const quality = run && run.metrics && run.metrics.quality;
  if (!quality || typeof quality !== "object") return null;
  return {
    profile_id: String(run.profile_id || ""),
    held_out_basis_points: Number(quality.held_out_basis_points) || 0,
    breadth_basis_points: Number(quality.breadth_basis_points) || 0,
    anti_shortcut_basis_points: Number(quality.anti_shortcut_basis_points) || 0,
    recorded_overall_basis_points: Number(quality.overall_basis_points) || 0,
  };
}

export function summarizeFromRuns(document) {
  const runs = Array.isArray(document && document.runs) ? document.runs : [];
  const byProfile = new Map();
  for (const run of runs) {
    const quality = extractRunQuality(run);
    if (!quality || !quality.profile_id) continue;
    const cost = Number(run.metrics && run.metrics.cost_usd);
    const wall = Number(run.metrics && run.metrics.wall_time_ms);
    const churn = Number(run.metrics && run.metrics.churn_count);
    let bucket = byProfile.get(quality.profile_id);
    if (!bucket) {
      bucket = {
        profile_id: quality.profile_id,
        count: 0,
        held_out_total: 0,
        breadth_total: 0,
        anti_shortcut_total: 0,
        recorded_overall_total: 0,
        cost_total: 0,
        cost_count: 0,
        wall_total: 0,
        wall_count: 0,
        churn_total: 0,
        churn_count: 0,
      };
      byProfile.set(quality.profile_id, bucket);
    }
    bucket.count += 1;
    bucket.held_out_total += quality.held_out_basis_points;
    bucket.breadth_total += quality.breadth_basis_points;
    bucket.anti_shortcut_total += quality.anti_shortcut_basis_points;
    bucket.recorded_overall_total += quality.recorded_overall_basis_points;
    if (Number.isFinite(cost)) {
      bucket.cost_total += cost;
      bucket.cost_count += 1;
    }
    if (Number.isFinite(wall)) {
      bucket.wall_total += wall;
      bucket.wall_count += 1;
    }
    if (Number.isFinite(churn)) {
      bucket.churn_total += churn;
      bucket.churn_count += 1;
    }
  }
  return Array.from(byProfile.values());
}

export function summarizeFromProfileSummaries(document) {
  const summaries = Array.isArray(document && document.profile_summaries)
    ? document.profile_summaries
    : [];
  return summaries
    .map((summary) => {
      const quality = summary.mean_quality || {};
      const held = quality.held_out_basis_points || {};
      const breadth = quality.breadth_basis_points || {};
      const anti = quality.anti_shortcut_basis_points || {};
      const recorded = quality.overall_basis_points || {};
      const wall = summary.mean_wall_time_ms || {};
      const churn = summary.mean_churn_count || {};
      const count = Number(held.count || recorded.count || summary.repetitions) || 0;
      return {
        profile_id: String(summary.profile_id || ""),
        count,
        held_out_total: Number(held.total) || 0,
        breadth_total: Number(breadth.total) || 0,
        anti_shortcut_total: Number(anti.total) || 0,
        recorded_overall_total: Number(recorded.total) || 0,
        cost_total: Number(summary.mean_cost_usd) * (count || 1),
        cost_count: count || 1,
        wall_total: Number(wall.total) || 0,
        wall_count: Number(wall.count) || 0,
        churn_total: Number(churn.total) || 0,
        churn_count: Number(churn.count) || 0,
        recorded_pareto_optimal: Boolean(summary.pareto_optimal),
      };
    })
    .filter((row) => row.profile_id);
}

export function loadEvaluationDocument(document) {
  if (!document || typeof document !== "object") {
    throw new Error("evaluation document must be a JSON object");
  }
  const fromRuns = summarizeFromRuns(document);
  const rows = fromRuns.length > 0 ? fromRuns : summarizeFromProfileSummaries(document);
  if (rows.length === 0) {
    throw new Error("evaluation document has no profile_summaries or scored runs");
  }
  const evidence = document.evidence && typeof document.evidence === "object" ? document.evidence : {};
  const pareto = document.pareto_conclusion && typeof document.pareto_conclusion === "object"
    ? document.pareto_conclusion
    : {};
  return {
    experiment_id: String(document.experiment_id || "unknown"),
    version: document.version,
    source: fromRuns.length > 0 ? "runs" : "summary",
    evidence_kind: String(evidence.kind || ""),
    eligible_for_production: evidence.eligible_for_production_or_default_decisions === true,
    pareto_status: String(pareto.status || ""),
    rows,
  };
}

export function rescoreLoaded(loaded, profile, document) {
  const objective = cloneObjective(profile);
  const errors = validateObjective(objective);
  const rows =
    loaded.source === "runs" && document
      ? rescoreFromRuns(document, objective)
      : loaded.rows.map((row) => rescoreRow(row, objective));
  const frontier = paretoFrontier(rows);
  const selection = selectProfile(rows, objective);
  return {
    objective,
    errors,
    rows,
    frontier,
    selection,
    labeled_preview: !loaded.eligible_for_production,
  };
}

export function rescoreFromRuns(document, profile) {
  const grouped = new Map();
  for (const run of Array.isArray(document.runs) ? document.runs : []) {
    const quality = extractRunQuality(run);
    if (!quality || !quality.profile_id) continue;
    const preview = rescoreQualityComponents(quality, profile.quality);
    const cost = Number(run.metrics && run.metrics.cost_usd);
    const wall = Number(run.metrics && run.metrics.wall_time_ms);
    const churn = Number(run.metrics && run.metrics.churn_count);
    let bucket = grouped.get(quality.profile_id);
    if (!bucket) {
      bucket = {
        profile_id: quality.profile_id,
        count: 0,
        recorded_overall_total: 0,
        preview_overall_total: 0,
        cost_total: 0,
        cost_count: 0,
        wall_total: 0,
        wall_count: 0,
        churn_total: 0,
        churn_count: 0,
      };
      grouped.set(quality.profile_id, bucket);
    }
    bucket.count += 1;
    bucket.recorded_overall_total += quality.recorded_overall_basis_points;
    bucket.preview_overall_total += preview;
    if (Number.isFinite(cost)) {
      bucket.cost_total += cost;
      bucket.cost_count += 1;
    }
    if (Number.isFinite(wall)) {
      bucket.wall_total += wall;
      bucket.wall_count += 1;
    }
    if (Number.isFinite(churn)) {
      bucket.churn_total += churn;
      bucket.churn_count += 1;
    }
  }
  return Array.from(grouped.values()).map((bucket) => ({
    profile_id: bucket.profile_id,
    count: bucket.count,
    recorded_overall: bucket.recorded_overall_total / bucket.count,
    preview_overall: bucket.preview_overall_total / bucket.count,
    mean_cost: bucket.cost_count ? bucket.cost_total / bucket.cost_count : 0,
    mean_wall: bucket.wall_count ? bucket.wall_total / bucket.wall_count : 0,
    mean_churn: bucket.churn_count ? bucket.churn_total / bucket.churn_count : 0,
    recorded_pareto_optimal: false,
    preview_overall_total: bucket.preview_overall_total,
  }));
}

export function rescoreRow(row, profile) {
  const count = row.count || 1;
  const preview_overall_total = rescoreQualityComponents(
    {
      held_out_basis_points: row.held_out_total,
      breadth_basis_points: row.breadth_total,
      anti_shortcut_basis_points: row.anti_shortcut_total,
    },
    profile.quality,
  );
  const recorded_overall = row.recorded_overall_total / count;
  const preview_overall = preview_overall_total / count;
  const mean_cost = row.cost_count ? row.cost_total / row.cost_count : 0;
  const mean_wall = row.wall_count ? row.wall_total / row.wall_count : 0;
  const mean_churn = row.churn_count ? row.churn_total / row.churn_count : 0;
  return {
    profile_id: row.profile_id,
    count,
    recorded_overall,
    preview_overall,
    mean_cost,
    mean_wall,
    mean_churn,
    recorded_pareto_optimal: Boolean(row.recorded_pareto_optimal),
    preview_overall_total,
  };
}

export function dominatesCostQuality(candidate, other) {
  const noMoreExpensive = candidate.mean_cost <= other.mean_cost;
  const noLowerQuality = candidate.preview_overall >= other.preview_overall;
  const strictlyBetter =
    candidate.mean_cost < other.mean_cost || candidate.preview_overall > other.preview_overall;
  return noMoreExpensive && noLowerQuality && strictlyBetter;
}

export function paretoFrontier(rows) {
  return rows.filter(
    (row, index) =>
      !rows.some((other, otherIndex) => otherIndex !== index && dominatesCostQuality(other, row)),
  );
}

export function selectProfile(rows, profile) {
  if (!rows.length) return null;
  const maxCost = Math.max(...rows.map((row) => row.mean_cost), 0);
  const maxWall = Math.max(...rows.map((row) => row.mean_wall), 0);
  const maxChurn = Math.max(...rows.map((row) => row.mean_churn), 0);
  const axes = profile.axes;
  const axisTotal = axisWeightSum(profile) || 1;
  const scored = rows.map((row) => {
    const qualityTerm = (row.preview_overall / 10000) * (axes.quality / axisTotal);
    const costTerm =
      maxCost > 0 ? (row.mean_cost / maxCost) * (axes.cost / axisTotal) : 0;
    const latencyTerm =
      maxWall > 0 ? (row.mean_wall / maxWall) * (axes.latency / axisTotal) : 0;
    const reworkTerm =
      maxChurn > 0 ? (row.mean_churn / maxChurn) * (axes.rework / axisTotal) : 0;
    const score = qualityTerm - costTerm - latencyTerm - reworkTerm;
    return { ...row, score };
  });
  scored.sort((left, right) => {
    if (right.score !== left.score) return right.score - left.score;
    if (left.mean_cost !== right.mean_cost) return left.mean_cost - right.mean_cost;
    return left.profile_id.localeCompare(right.profile_id);
  });
  return scored[0];
}

function clampWeight(value, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  if (number < 0) return 0;
  if (number > 100) return 100;
  return Math.round(number);
}
