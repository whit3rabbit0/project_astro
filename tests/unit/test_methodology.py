import pytest

from astro.intel.methodology import MethodologyTracker, PTES_PHASES


@pytest.fixture
def tracker():
    return MethodologyTracker()


class TestRecordToolUsage:
    def test_transitions_phase_to_in_progress(self, tracker):
        tracker.record_tool_usage("nmap")
        assert tracker.phases["intelligence_gathering"]["status"] == "in_progress"

    def test_returns_affected_phase_ids(self, tracker):
        affected = tracker.record_tool_usage("nmap")
        assert "intelligence_gathering" in affected

    def test_tool_affecting_multiple_phases(self, tracker):
        affected = tracker.record_tool_usage("nmap")
        assert "intelligence_gathering" in affected
        assert "vulnerability_analysis" in affected

    def test_duplicate_tool_usage_not_recorded_twice(self, tracker):
        tracker.record_tool_usage("nmap")
        affected = tracker.record_tool_usage("nmap")
        assert affected == []
        assert tracker.phases["intelligence_gathering"]["tools_used"].count("nmap") == 1

    def test_sets_started_at_timestamp(self, tracker):
        tracker.record_tool_usage("nmap")
        assert tracker.phases["intelligence_gathering"]["started_at"] is not None

    def test_unknown_tool_affects_no_phases(self, tracker):
        affected = tracker.record_tool_usage("unknown_tool_xyz")
        assert affected == []


class TestCompletePhase:
    def test_marks_phase_completed(self, tracker):
        tracker.complete_phase("intelligence_gathering")
        assert tracker.phases["intelligence_gathering"]["status"] == "completed"

    def test_sets_completed_at_timestamp(self, tracker):
        tracker.complete_phase("intelligence_gathering")
        assert tracker.phases["intelligence_gathering"]["completed_at"] is not None

    def test_unknown_phase_is_noop(self, tracker):
        tracker.complete_phase("nonexistent_phase")


class TestGetCoverage:
    def test_all_not_started_initially(self, tracker):
        coverage = tracker.get_coverage()
        assert coverage["total_phases"] == len(PTES_PHASES)
        assert coverage["completed"] == 0
        assert coverage["in_progress"] == 0
        assert coverage["not_started"] == len(PTES_PHASES)
        assert coverage["coverage_percent"] == 0.0

    def test_coverage_after_completing_one_phase(self, tracker):
        tracker.complete_phase("intelligence_gathering")
        coverage = tracker.get_coverage()
        assert coverage["completed"] == 1
        expected_pct = round(1 / len(PTES_PHASES) * 100, 1)
        assert coverage["coverage_percent"] == expected_pct

    def test_coverage_tracks_in_progress(self, tracker):
        tracker.record_tool_usage("nmap")
        coverage = tracker.get_coverage()
        assert coverage["in_progress"] >= 1

    def test_phases_detail_in_coverage(self, tracker):
        tracker.record_tool_usage("nmap")
        coverage = tracker.get_coverage()
        phase_detail = coverage["phases"]["intelligence_gathering"]
        assert phase_detail["status"] == "in_progress"
        assert "nmap" in phase_detail["tools_used"]


class TestIncrementFindings:
    def test_increments_findings_count(self, tracker):
        tracker.increment_findings("intelligence_gathering", 3)
        assert tracker.phases["intelligence_gathering"]["findings_count"] == 3

    def test_multiple_increments_accumulate(self, tracker):
        tracker.increment_findings("exploitation", 2)
        tracker.increment_findings("exploitation", 5)
        assert tracker.phases["exploitation"]["findings_count"] == 7


class TestSuggestNextSteps:
    def test_suggests_not_started_phases_with_tools(self, tracker):
        suggestions = tracker.suggest_next_steps()
        phase_ids = [s["phase_id"] for s in suggestions]
        assert "intelligence_gathering" in phase_ids

    def test_suggests_remaining_tools_for_in_progress(self, tracker):
        tracker.record_tool_usage("nmap")
        suggestions = tracker.suggest_next_steps()
        ig_suggestion = next(
            s for s in suggestions if s["phase_id"] == "intelligence_gathering"
        )
        assert "nmap" not in ig_suggestion["tools"]
        assert len(ig_suggestion["tools"]) > 0

    def test_no_suggestion_for_completed_phases(self, tracker):
        tracker.complete_phase("intelligence_gathering")
        suggestions = tracker.suggest_next_steps()
        phase_ids = [s["phase_id"] for s in suggestions]
        assert "intelligence_gathering" not in phase_ids

    def test_no_suggestion_for_phases_without_tools(self, tracker):
        suggestions = tracker.suggest_next_steps()
        phase_ids = [s["phase_id"] for s in suggestions]
        assert "pre_engagement" not in phase_ids
        assert "threat_modeling" not in phase_ids
        assert "reporting" not in phase_ids
