package notify

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const ntfyBaseURL = "https://ntfy.sh"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// SendFailure sends a backup failure notification to the configured ntfy.sh topic.
// If topic is empty, it does nothing. Errors are logged but not returned because
// notification delivery is best-effort and should not affect the backup job result.
func SendFailure(topic string, jobID int64, errMsg string) {
	if topic == "" {
		return
	}
	msg := fmt.Sprintf("Backup job %d failed: %s", jobID, errMsg)
	send(topic, "Coldcrypt Backup Failed", msg, "rotating_light")
}

// SendPartialFailure sends a warning notification when a backup job completes
// but some files could not be backed up. If topic is empty, it does nothing.
func SendPartialFailure(topic string, jobID int64, errCount int) {
	if topic == "" {
		return
	}
	msg := fmt.Sprintf("Backup job %d completed with errors: %d file(s) could not be backed up. Check the log for details.", jobID, errCount)
	send(topic, "Coldcrypt Backup Warning", msg, "warning")
}

// SendLowStorage sends a critical storage alert when the backup destination
// volume is nearly full (0–9 % free). If topic is empty, it does nothing.
func SendLowStorage(topic string, percentFree int) {
	if topic == "" {
		return
	}
	msg := fmt.Sprintf("Remote backup storage is critically low: only %d%% free. Please free up space on the backup destination.", percentFree)
	send(topic, "Coldcrypt Storage Alert", msg, "warning,exclamation")
}

// SendTest sends a test notification to the configured ntfy.sh topic.
// Returns an error if the request fails or the topic is empty.
func SendTest(topic string) error {
	if topic == "" {
		return fmt.Errorf("ntfy_topic is not configured")
	}
	return send(topic, "Coldcrypt Test", "This is a test notification from Coldcrypt.", "white_check_mark")
}

func SendScanIssues(topic string, jobID int64, scanned, inconsistencies, errs int) {
	if topic == "" {
		return
	}
	msg := fmt.Sprintf("Integrity scan job %d: %d files scanned, %d inconsistenc(ies), %d error(s). Check job history for details.",
		jobID, scanned, inconsistencies, errs)
	send(topic, "Coldcrypt Integrity Scan Warning", msg, "warning,mag")
}

func send(topic, title, message, tags string) error {
	url := ntfyBaseURL + "/" + topic
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(message))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Title", title)
	req.Header.Set("Tags", tags)

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("notify: send to ntfy.sh topic %q failed: %v", topic, err)
		return fmt.Errorf("send notification: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		err := fmt.Errorf("ntfy.sh returned status %d", resp.StatusCode)
		log.Printf("notify: %v", err)
		return err
	}
	return nil
}
