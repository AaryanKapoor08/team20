// Shows the browser's passkey prompt and sends the device's answer back in the page's form.
// The server puts the passkey options in the button's data-options attribute.
// The form already has the CSRF token, so the answer is checked like any other form.

const passkeyButton = document.getElementById("passkey-button");
const passkeyForm = document.getElementById("passkey-form");
const credentialField = document.getElementById("passkey-credential");
const errorText = document.getElementById("passkey-error");

async function usePasskey() {
    const options = JSON.parse(passkeyButton.dataset.options);
    let answer;
    try {
        if (passkeyButton.dataset.mode === "register") {
            answer = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: options });
        } else {
            answer = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
        }
    } catch (error) {
        // The user closed the prompt, or this device has no passkey for this site
        errorText.textContent = "The passkey check did not finish. Try again.";
        errorText.hidden = false;
        return;
    }
    credentialField.value = JSON.stringify(answer);
    passkeyForm.submit();
}

passkeyButton.addEventListener("click", usePasskey);
