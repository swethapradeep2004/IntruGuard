document.addEventListener("DOMContentLoaded", () => {
  const detectBtn = document.getElementById("detectBtn");
  const uploadInput = document.getElementById("uploadFile");

  detectBtn.addEventListener("click", async () => {
    const file = uploadInput.files[0];
    if (!file) {
      alert("Please select a file");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("/detect", {
        method: "POST",
        body: formData
      });

      const result = await response.json();
      document.getElementById("detectResult").textContent = JSON.stringify(result);
    } catch (err) {
      console.error(err);
      alert("Detection failed");
    }
  });
});
