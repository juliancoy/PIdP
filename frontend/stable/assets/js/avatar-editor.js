(function () {
    var uiBase = (window.PIDP_UI_BASE || "").trim();
    var modal = document.getElementById("avatar-modal");
    if (!modal) {
        return;
    }

    var preview = document.getElementById("profile-avatar-preview");
    var openButton = document.getElementById("open-avatar-modal");
    var chooseButton = document.getElementById("choose-avatar-image");
    var uploadButton = document.getElementById("upload-avatar-image");
    var closeButtons = modal.querySelectorAll("[data-close-avatar-modal]");
    var fileInput = document.getElementById("avatar-file-input");
    var zoomInput = document.getElementById("avatar-zoom");
    var canvas = document.getElementById("avatar-editor-canvas");
    var status = document.getElementById("avatar-upload-status");
    var avatarUrlInput = document.getElementById("avatar_url");

    var context = canvas.getContext("2d");
    var image = null;
    var scale = 1;
    var baseScale = 1;
    var offsetX = 0;
    var offsetY = 0;
    var dragging = false;
    var dragStartX = 0;
    var dragStartY = 0;
    var startOffsetX = 0;
    var startOffsetY = 0;

    function setStatus(message, kind) {
        status.innerHTML = message
            ? '<div class="status ' + (kind || "") + '">' + message + "</div>"
            : "";
    }

    function openModal() {
        modal.classList.remove("hidden");
        modal.setAttribute("aria-hidden", "false");
    }

    function closeModal() {
        modal.classList.add("hidden");
        modal.setAttribute("aria-hidden", "true");
        setStatus("");
    }

    function updateSidebarAvatar(url) {
        var panel = document.querySelector(".profile-panel");
        if (!panel) {
            return;
        }
        var avatar = panel.querySelector(".profile-chip-avatar");
        if (avatar) {
            avatar.src = url;
            return;
        }
        var fallback = panel.querySelector(".profile-chip-fallback");
        if (!fallback) {
            return;
        }
        var img = document.createElement("img");
        img.className = "profile-chip-avatar";
        img.alt = "Profile avatar";
        img.src = url;
        fallback.replaceWith(img);
    }

    function draw() {
        context.clearRect(0, 0, canvas.width, canvas.height);
        context.fillStyle = "rgba(255,255,255,0.25)";
        context.fillRect(0, 0, canvas.width, canvas.height);

        if (!image) {
            context.fillStyle = "rgba(80,80,80,0.7)";
            context.font = "600 18px IBM Plex Sans, sans-serif";
            context.textAlign = "center";
            context.fillText("Choose an image", canvas.width / 2, canvas.height / 2);
            return;
        }

        var drawWidth = image.width * scale;
        var drawHeight = image.height * scale;
        var x = (canvas.width - drawWidth) / 2 + offsetX;
        var y = (canvas.height - drawHeight) / 2 + offsetY;
        context.drawImage(image, x, y, drawWidth, drawHeight);
    }

    function loadImage(file) {
        return new Promise(function (resolve, reject) {
            var reader = new FileReader();
            reader.onload = function () {
                var img = new Image();
                img.onload = function () {
                    resolve(img);
                };
                img.onerror = reject;
                img.src = reader.result;
            };
            reader.onerror = reject;
            reader.readAsDataURL(file);
        });
    }

    function fitImage(img) {
        image = img;
        baseScale = Math.max(canvas.width / img.width, canvas.height / img.height);
        scale = baseScale;
        offsetX = 0;
        offsetY = 0;
        zoomInput.value = "1";
        draw();
    }

    function exportBlob() {
        return new Promise(function (resolve) {
            var output = document.createElement("canvas");
            output.width = 512;
            output.height = 512;
            var out = output.getContext("2d");

            var cropInset = canvas.width * 0.12;
            var cropSize = canvas.width - cropInset * 2;
            out.save();
            out.beginPath();
            out.arc(256, 256, 256, 0, Math.PI * 2);
            out.closePath();
            out.clip();

            var drawWidth = image.width * scale;
            var drawHeight = image.height * scale;
            var sourceX = (canvas.width - drawWidth) / 2 + offsetX;
            var sourceY = (canvas.height - drawHeight) / 2 + offsetY;
            var ratio = 512 / cropSize;

            out.drawImage(
                image,
                (cropInset - sourceX) / scale,
                (cropInset - sourceY) / scale,
                cropSize / scale,
                cropSize / scale,
                0,
                0,
                512,
                512
            );
            out.restore();
            output.toBlob(function (blob) {
                resolve(blob);
            }, "image/png");
        });
    }

    async function uploadAvatar() {
        if (!image) {
            setStatus("Choose an image first.", "error");
            return;
        }

        uploadButton.disabled = true;
        setStatus("Uploading avatar...");
        try {
            var uploadConfigResponse = await fetch("/auth/avatar/upload-url", {
                method: "POST",
                credentials: "same-origin"
            });
            if (!uploadConfigResponse.ok) {
                throw new Error("Could not prepare avatar upload.");
            }
            var uploadConfig = await uploadConfigResponse.json();
            var blob = await exportBlob();

            var uploadResponse = await fetch(uploadConfig.upload_url, {
                method: "PUT",
                headers: {
                    "Content-Type": "image/png"
                },
                body: blob
            });
            if (!uploadResponse.ok) {
                throw new Error("Image upload failed.");
            }

            var commitResponse = await fetch(uiBase + "/profile/avatar", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    avatar_url: uploadConfig.public_url,
                    object_key: uploadConfig.object_key
                })
            });
            if (!commitResponse.ok) {
                throw new Error("Could not save avatar to profile.");
            }

            if (preview && preview.tagName === "IMG") {
                preview.src = uploadConfig.public_url;
            } else if (preview) {
                var img = document.createElement("img");
                img.className = preview.className;
                img.id = preview.id;
                img.alt = "Profile avatar";
                img.src = uploadConfig.public_url;
                preview.replaceWith(img);
                preview = img;
            }
            if (avatarUrlInput) {
                avatarUrlInput.value = uploadConfig.public_url;
            }
            updateSidebarAvatar(uploadConfig.public_url);

            setStatus("Avatar uploaded.", "success");
        } catch (error) {
            setStatus(error.message || "Upload failed.", "error");
        } finally {
            uploadButton.disabled = false;
        }
    }

    openButton.addEventListener("click", function () {
        openModal();
        draw();
    });

    chooseButton.addEventListener("click", function () {
        fileInput.click();
    });

    closeButtons.forEach(function (button) {
        button.addEventListener("click", closeModal);
    });

    fileInput.addEventListener("change", async function () {
        var file = fileInput.files && fileInput.files[0];
        if (!file) {
            return;
        }
        try {
            var img = await loadImage(file);
            fitImage(img);
            setStatus("");
        } catch (_error) {
            setStatus("Could not read that image.", "error");
        }
    });

    zoomInput.addEventListener("input", function () {
        scale = baseScale * Number(zoomInput.value || 1);
        draw();
    });

    canvas.addEventListener("pointerdown", function (event) {
        if (!image) {
            return;
        }
        dragging = true;
        dragStartX = event.clientX;
        dragStartY = event.clientY;
        startOffsetX = offsetX;
        startOffsetY = offsetY;
        canvas.classList.add("dragging");
        canvas.setPointerCapture(event.pointerId);
    });

    canvas.addEventListener("pointermove", function (event) {
        if (!dragging) {
            return;
        }
        offsetX = startOffsetX + (event.clientX - dragStartX);
        offsetY = startOffsetY + (event.clientY - dragStartY);
        draw();
    });

    function stopDragging(event) {
        if (!dragging) {
            return;
        }
        dragging = false;
        canvas.classList.remove("dragging");
        if (event && canvas.hasPointerCapture(event.pointerId)) {
            canvas.releasePointerCapture(event.pointerId);
        }
    }

    canvas.addEventListener("pointerup", stopDragging);
    canvas.addEventListener("pointercancel", stopDragging);

    uploadButton.addEventListener("click", uploadAvatar);
    draw();
}());
