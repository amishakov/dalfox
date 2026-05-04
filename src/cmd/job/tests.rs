use super::*;

#[test]
fn test_parse_job_status_round_trip() {
    for status in [
        JobStatus::Queued,
        JobStatus::Running,
        JobStatus::Done,
        JobStatus::Error,
        JobStatus::Cancelled,
    ] {
        let s = status.to_string();
        assert_eq!(parse_job_status(&s), Some(status));
    }
    assert_eq!(parse_job_status("unknown"), None);
}

#[test]
fn test_new_queued_initializes_timestamps() {
    let before = now_ms();
    let job = Job::new_queued("https://example.com".to_string());
    let after = now_ms();
    assert_eq!(job.status, JobStatus::Queued);
    assert!(job.queued_at_ms >= before && job.queued_at_ms <= after);
    assert!(job.started_at_ms.is_none());
    assert!(job.finished_at_ms.is_none());
    assert!(!job.is_terminal());
}

#[test]
fn test_duration_ms_computed_from_timestamps() {
    let mut job = Job::new_queued("https://example.com".to_string());
    assert_eq!(job.duration_ms(), None);
    job.started_at_ms = Some(1000);
    job.finished_at_ms = Some(1250);
    assert_eq!(job.duration_ms(), Some(250));
}

#[test]
fn test_purge_expired_jobs_removes_old_terminal_jobs() {
    let mut jobs = HashMap::new();
    let mut old = Job::new_queued("old".to_string());
    old.status = JobStatus::Done;
    old.finished_at_ms = Some(now_ms() - (JOB_RETENTION_SECS + 10) * 1000);
    jobs.insert("old".to_string(), old);

    let mut fresh = Job::new_queued("fresh".to_string());
    fresh.status = JobStatus::Done;
    fresh.finished_at_ms = Some(now_ms());
    jobs.insert("fresh".to_string(), fresh);

    jobs.insert("active".to_string(), Job::new_queued("active".to_string()));

    purge_expired_jobs(&mut jobs, JOB_RETENTION_SECS);

    assert!(
        !jobs.contains_key("old"),
        "old terminal job should be purged"
    );
    assert!(jobs.contains_key("fresh"), "fresh terminal job must remain");
    assert!(
        jobs.contains_key("active"),
        "active job must never be purged"
    );
}
