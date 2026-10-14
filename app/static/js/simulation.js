function copyToClipboard(elementId, feedbackId) {
  const element = document.getElementById(elementId);
  if (!element) return;
  const text = element.innerText || element.value;

  navigator.clipboard.writeText(text).then(() => {
    const feedback = document.getElementById(feedbackId);
    if (feedback) {
      const originalText = feedback.innerText;
      feedback.innerText = "Copied!";
      feedback.style.color = "#10b981";
      setTimeout(() => {
        feedback.innerText = originalText;
        feedback.style.color = "";
      }, 2000);
    }
  }).catch(err => {
    console.error("Failed to copy:", err);
  });
}

function selectEmail(email) {
  const input = document.getElementById("emailInput");
  if (input) {
    input.value = email;
    input.focus();
  }
}
