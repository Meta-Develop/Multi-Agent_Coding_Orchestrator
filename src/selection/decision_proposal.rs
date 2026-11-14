//! Pure decision-proposal surface over admitted selector candidates.
//!
//! A decision model may later propose a choice among the candidates the
//! deterministic selector already admitted (#969, first slice of #829). This
//! module builds the question from a `SelectionProvenance` and adopts or
//! rejects a proposal without touching any binding gate.

use serde::{Deserialize, Serialize};

use super::{CandidateEvaluation, CandidateKey, DecisionStatus, SelectionProvenance, TaskProfile};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionOption {
    pub option_id: String,
    pub candidate: CandidateKey,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionQuestion {
    pub task_text: String,
    pub task: TaskProfile,
    pub deterministic_choice: Option<CandidateKey>,
    pub options: Vec<DecisionOption>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionOptionProbability {
    pub option_id: String,
    pub probability_basis_points: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionProposal {
    pub decision_model: String,
    pub decision_model_version: String,
    pub probabilities: Vec<DecisionOptionProbability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAdoptionOutcome {
    Adopted,
    BelowThreshold,
    Malformed,
    NoOptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionAdoption {
    pub decision_model: String,
    pub decision_model_version: String,
    pub threshold_basis_points: u16,
    pub probabilities: Vec<DecisionOptionProbability>,
    pub proposed_option_id: Option<String>,
    pub confidence_basis_points: Option<u16>,
    pub outcome: DecisionAdoptionOutcome,
    pub adopted: bool,
    pub reason: String,
    pub deterministic_choice: Option<CandidateKey>,
    pub final_choice: Option<CandidateKey>,
}

fn describe_candidate(evaluation: &CandidateEvaluation) -> String {
    let limitations = if evaluation.prior_limitations.is_empty() {
        "none".to_string()
    } else {
        evaluation.prior_limitations.join(", ")
    };
    let (quality, cost) = match &evaluation.score {
        Some(score) => (
            score.posterior_quality_basis_points.to_string(),
            score
                .expected_total_cost_per_accepted_task_microunits
                .to_string(),
        ),
        None => ("unknown".to_string(), "unknown".to_string()),
    };
    let quota_reason = if evaluation.quota.reason.is_empty() {
        "none".to_string()
    } else {
        evaluation.quota.reason.clone()
    };
    format!(
        "{}/{}/{}; prior {} observed {}; scope {}; limitations {}; posterior quality {} bp; \
expected cost per accepted task {} microunits; quota {}",
        evaluation.candidate.runtime,
        evaluation.candidate.model,
        evaluation.candidate.effort.as_str(),
        evaluation.prior_source_id.as_deref().unwrap_or("unknown"),
        evaluation.prior_observed_on.as_deref().unwrap_or("unknown"),
        evaluation.prior_scope.as_deref().unwrap_or("unknown"),
        limitations,
        quality,
        cost,
        quota_reason
    )
}

pub fn decision_question(task_text: &str, provenance: &SelectionProvenance) -> DecisionQuestion {
    let deterministic_choice = provenance
        .choice
        .as_ref()
        .map(|choice| choice.candidate.clone());
    let mut index = 0usize;
    let options = if provenance.status == DecisionStatus::Selected {
        provenance
            .candidate_set
            .iter()
            .filter(|evaluation| evaluation.eligible)
            .map(|evaluation| {
                index += 1;
                DecisionOption {
                    option_id: format!("option-{index}"),
                    candidate: evaluation.candidate.clone(),
                    description: describe_candidate(evaluation),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    DecisionQuestion {
        task_text: task_text.to_string(),
        task: provenance.normalized_task.clone(),
        deterministic_choice,
        options,
    }
}

pub fn adopt_decision_proposal(
    question: &DecisionQuestion,
    proposal: &DecisionProposal,
    threshold_basis_points: u16,
) -> DecisionAdoption {
    let deterministic_choice = question.deterministic_choice.clone();
    let base = |outcome: DecisionAdoptionOutcome,
                proposed_option_id: Option<String>,
                confidence_basis_points: Option<u16>,
                adopted: bool,
                reason: String,
                final_choice: Option<CandidateKey>| DecisionAdoption {
        decision_model: proposal.decision_model.clone(),
        decision_model_version: proposal.decision_model_version.clone(),
        threshold_basis_points,
        probabilities: proposal.probabilities.clone(),
        proposed_option_id,
        confidence_basis_points,
        outcome,
        adopted,
        reason,
        deterministic_choice: deterministic_choice.clone(),
        final_choice,
    };
    if question.options.is_empty() {
        return base(
            DecisionAdoptionOutcome::NoOptions,
            None,
            None,
            false,
            "no admitted options".to_string(),
            deterministic_choice.clone(),
        );
    }
    let malformed = |reason: String| {
        base(
            DecisionAdoptionOutcome::Malformed,
            None,
            None,
            false,
            reason,
            deterministic_choice.clone(),
        )
    };
    if threshold_basis_points == 0 || threshold_basis_points > 10000 {
        return malformed(format!(
            "threshold {threshold_basis_points} bp out of range"
        ));
    }
    if proposal.probabilities.is_empty() {
        return malformed("empty probabilities".to_string());
    }
    for probability in &proposal.probabilities {
        if !question
            .options
            .iter()
            .any(|option| option.option_id == probability.option_id)
        {
            return malformed(format!("unknown option {}", probability.option_id));
        }
        if proposal
            .probabilities
            .iter()
            .filter(|other| other.option_id == probability.option_id)
            .count()
            > 1
        {
            return malformed(format!("repeated option {}", probability.option_id));
        }
        if probability.probability_basis_points > 10000 {
            return malformed(format!(
                "probability for {} above 10000 bp",
                probability.option_id
            ));
        }
    }
    let sum: u32 = proposal
        .probabilities
        .iter()
        .map(|probability| probability.probability_basis_points as u32)
        .sum();
    if !(9900..=10100).contains(&sum) {
        return malformed(format!("probabilities sum to {sum} bp"));
    }
    let top = proposal
        .probabilities
        .iter()
        .max_by_key(|probability| probability.probability_basis_points)
        .expect("probabilities are non-empty");
    let top_probability = top.probability_basis_points;
    let tied = proposal
        .probabilities
        .iter()
        .filter(|other| other.probability_basis_points == top_probability)
        .count()
        > 1;
    if tied {
        return base(
            DecisionAdoptionOutcome::BelowThreshold,
            None,
            Some(top_probability),
            false,
            "tied top options".to_string(),
            deterministic_choice.clone(),
        );
    }
    if top_probability >= threshold_basis_points {
        let candidate = question
            .options
            .iter()
            .find(|option| option.option_id == top.option_id)
            .map(|option| option.candidate.clone());
        return base(
            DecisionAdoptionOutcome::Adopted,
            Some(top.option_id.clone()),
            Some(top_probability),
            true,
            format!("adopted {} at {} bp", top.option_id, top_probability),
            candidate,
        );
    }
    base(
        DecisionAdoptionOutcome::BelowThreshold,
        Some(top.option_id.clone()),
        Some(top_probability),
        false,
        format!(
            "{} at {} bp is below the threshold {} bp",
            top.option_id, top_probability, threshold_basis_points
        ),
        deterministic_choice.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> SelectionProvenance {
        crate::selection::select(&crate::selection::selection_test_base_input())
            .expect("base input selects")
    }

    fn probability(option_id: &str, probability_basis_points: u16) -> DecisionOptionProbability {
        DecisionOptionProbability {
            option_id: option_id.to_string(),
            probability_basis_points,
        }
    }

    fn proposal(probabilities: Vec<DecisionOptionProbability>) -> DecisionProposal {
        DecisionProposal {
            decision_model: "decision-model".to_string(),
            decision_model_version: "1".to_string(),
            probabilities,
        }
    }

    fn question_with_options(count: usize) -> DecisionQuestion {
        let mut provenance = provenance();
        let template = provenance
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.eligible)
            .expect("an eligible candidate")
            .clone();
        provenance.candidate_set = (0..count)
            .map(|index| {
                let mut evaluation = template.clone();
                evaluation.candidate.model = format!("model-{index}");
                evaluation
            })
            .collect();
        if let Some(choice) = provenance.choice.as_mut() {
            choice.candidate = provenance.candidate_set[0].candidate.clone();
        }
        decision_question("sample task", &provenance)
    }

    #[test]
    fn question_lists_only_eligible_candidates() {
        let mut provenance = provenance();
        let template = provenance
            .candidate_set
            .iter()
            .find(|evaluation| evaluation.eligible)
            .expect("an eligible candidate")
            .clone();
        let mut ineligible = template.clone();
        ineligible.candidate.model = "model-ineligible".to_string();
        ineligible.eligible = false;
        let mut first = template.clone();
        first.candidate.model = "model-a".to_string();
        let mut second = template.clone();
        second.candidate.model = "model-b".to_string();
        provenance.candidate_set = vec![first, ineligible, second];
        if let Some(choice) = provenance.choice.as_mut() {
            choice.candidate = provenance.candidate_set[0].candidate.clone();
        }
        let question = decision_question("do the thing", &provenance);
        assert_eq!(question.task_text, "do the thing");
        assert_eq!(
            question.deterministic_choice,
            provenance
                .choice
                .as_ref()
                .map(|choice| choice.candidate.clone())
        );
        let ids: Vec<&str> = question
            .options
            .iter()
            .map(|option| option.option_id.as_str())
            .collect();
        assert_eq!(ids, vec!["option-1", "option-2"]);
        let candidates: Vec<CandidateKey> = question
            .options
            .iter()
            .map(|option| option.candidate.clone())
            .collect();
        assert_eq!(
            candidates,
            vec![
                provenance.candidate_set[0].candidate.clone(),
                provenance.candidate_set[2].candidate.clone(),
            ]
        );
        for option in &question.options {
            assert!(option.description.starts_with(&format!(
                "{}/{}/{};",
                option.candidate.runtime,
                option.candidate.model,
                option.candidate.effort.as_str()
            )));
            assert!(option.description.contains("posterior quality"));
        }
        provenance.status = DecisionStatus::FailClosed;
        assert!(decision_question("do the thing", &provenance)
            .options
            .is_empty());
    }

    #[test]
    fn adopted_proposal_selects_an_admitted_option() {
        let question = question_with_options(2);
        let deterministic = question.deterministic_choice.clone();
        let other = question
            .options
            .iter()
            .find(|option| Some(option.candidate.clone()) != deterministic)
            .expect("a non-deterministic option");
        let adoption = adopt_decision_proposal(
            &question,
            &proposal(vec![
                probability(&other.option_id, 8000),
                probability("option-1", 2000),
            ]),
            6000,
        );
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::Adopted);
        assert!(adoption.adopted);
        assert_eq!(adoption.final_choice, Some(other.candidate.clone()));
        assert_eq!(adoption.confidence_basis_points, Some(8000));
    }

    #[test]
    fn below_threshold_and_ties_keep_the_deterministic_choice() {
        let question = question_with_options(2);
        let tie = adopt_decision_proposal(
            &question,
            &proposal(vec![
                probability("option-1", 5000),
                probability("option-2", 5000),
            ]),
            6000,
        );
        assert_eq!(tie.outcome, DecisionAdoptionOutcome::BelowThreshold);
        assert_eq!(tie.reason, "tied top options");
        assert_eq!(tie.final_choice, question.deterministic_choice);
        let below = adopt_decision_proposal(
            &question,
            &proposal(vec![
                probability("option-1", 5500),
                probability("option-2", 4500),
            ]),
            6000,
        );
        assert_eq!(below.outcome, DecisionAdoptionOutcome::BelowThreshold);
        assert_eq!(below.proposed_option_id.as_deref(), Some("option-1"));
        assert_eq!(below.final_choice, question.deterministic_choice);
    }

    #[test]
    fn malformed_proposals_keep_the_deterministic_choice() {
        let question = question_with_options(2);
        let deterministic = question.deterministic_choice.clone();
        let cases: Vec<(Vec<DecisionOptionProbability>, u16)> = vec![
            (vec![probability("option-9", 10000)], 6000),
            (
                vec![probability("option-1", 5000), probability("option-1", 5000)],
                6000,
            ),
            (
                vec![probability("option-1", 4500), probability("option-2", 4500)],
                6000,
            ),
            (vec![], 6000),
            (
                vec![probability("option-1", 6000), probability("option-2", 4000)],
                0,
            ),
            (
                vec![probability("option-1", 6000), probability("option-2", 4000)],
                10001,
            ),
        ];
        for (probabilities, threshold) in cases {
            let adoption = adopt_decision_proposal(&question, &proposal(probabilities), threshold);
            assert_eq!(adoption.outcome, DecisionAdoptionOutcome::Malformed);
            assert!(!adoption.adopted);
            assert_eq!(adoption.final_choice, deterministic);
        }
        let empty = DecisionQuestion {
            task_text: String::new(),
            task: question.task.clone(),
            deterministic_choice: deterministic,
            options: Vec::new(),
        };
        let adoption = adopt_decision_proposal(
            &empty,
            &proposal(vec![probability("option-1", 10000)]),
            6000,
        );
        assert_eq!(adoption.outcome, DecisionAdoptionOutcome::NoOptions);
        assert_eq!(adoption.reason, "no admitted options");
    }

    #[test]
    fn adoption_record_round_trips() {
        let question = question_with_options(2);
        let adoption = adopt_decision_proposal(
            &question,
            &proposal(vec![
                probability("option-1", 5500),
                probability("option-2", 4500),
            ]),
            6000,
        );
        assert_eq!(
            serde_json::to_string(&adoption.outcome).unwrap(),
            "\"below_threshold\""
        );
        let adoption_json = serde_json::to_string(&adoption).unwrap();
        assert_eq!(
            serde_json::from_str::<DecisionAdoption>(&adoption_json).unwrap(),
            adoption
        );
        let question_json = serde_json::to_string(&question).unwrap();
        assert_eq!(
            serde_json::from_str::<DecisionQuestion>(&question_json).unwrap(),
            question
        );
        let proposal_json = serde_json::to_string(&proposal(Vec::new())).unwrap();
        let rejected = proposal_json.replacen("{", "{\"unexpected\":1,", 1);
        assert!(serde_json::from_str::<DecisionProposal>(&rejected).is_err());
    }
}
