const WORKER_URL = "https://YOUR-WORKER.workers.dev";

let photoBlob = null;
let locationData = null;
let cameraStream = null;

const status = document.getElementById("status");
const submit = document.getElementById("submitBtn");

function updateSubmit() {
  submit.disabled = !(photoBlob || locationData);
}

document.getElementById("cameraBtn").onclick = async () => {
  try {
    cameraStream =
      await navigator.mediaDevices.getUserMedia({ video: true });

    const video = document.getElementById("video");

    video.srcObject = cameraStream;
    video.hidden = false;

    document.getElementById("captureBtn").hidden = false;

    status.textContent =
      "Camera enabled. Ab Take Photo press karein.";
  } catch {
    status.textContent =
      "Camera permission denied.";
  }
};

document.getElementById("captureBtn").onclick = () => {
  const video = document.getElementById("video");

  const canvas = document.createElement("canvas");

  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;

  canvas.getContext("2d").drawImage(
    video,
    0,
    0,
    canvas.width,
    canvas.height
  );

  canvas.toBlob(blob => {
    photoBlob = blob;

    status.textContent =
      "Photo ready. Send button press karne par hi upload hoga.";

    updateSubmit();
  }, "image/jpeg", 0.9);
};

document.getElementById("micBtn").onclick = async () => {
  try {
    const stream =
      await navigator.mediaDevices.getUserMedia({
        audio: true
      });

    status.textContent =
      "Microphone permission granted. Audio upload nahi kiya ja raha.";

    stream.getTracks().forEach(track => track.stop());

  } catch {
    status.textContent =
      "Microphone permission denied.";
  }
};

document.getElementById("locationBtn").onclick = () => {

  if (!navigator.geolocation) {
    status.textContent =
      "Location supported nahi hai.";
    return;
  }

  navigator.geolocation.getCurrentPosition(
    position => {

      locationData = {
        latitude: position.coords.latitude,
        longitude: position.coords.longitude
      };

      status.textContent =
        "Location received successfully.";

      updateSubmit();
    },

    () => {
      status.textContent =
        "Location permission denied.";
    }
  );
};

submit.onclick = async () => {

  if (!photoBlob && !locationData) return;

  if (WORKER_URL.includes("YOUR-WORKER")) {
    status.textContent =
      "Pehle Cloudflare Worker URL add karein.";
    return;
  }

  submit.disabled = true;

  const form = new FormData();

  if (photoBlob) {
    form.append("photo", photoBlob, "photo.jpg");
  }

  if (locationData) {
    form.append(
      "location",
      JSON.stringify(locationData)
    );
  }

  try {

    const response = await fetch(WORKER_URL, {
      method: "POST",
      body: form
    });

    const result = await response.json();

    status.textContent =
      result.ok
        ? "Approved data Telegram par send ho gaya."
        : "Server ne request reject kar di.";

  } catch {

    status.textContent =
      "Server se connection nahi ho paya.";

  } finally {

    submit.disabled = false;
  }
};
