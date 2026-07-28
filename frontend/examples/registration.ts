import {
  ContextPasswordChecker,
  HibpPwnedPasswordClient,
  PasswordBlocklist,
  PasswordPolicy,
  ZxcvbnTsStrengthEstimator,
} from '../src/index.js'

const form = document.querySelector<HTMLFormElement>('#registration-form')
const passwordInput = document.querySelector<HTMLInputElement>('#password')
const usernameInput = document.querySelector<HTMLInputElement>('#username')
const emailInput = document.querySelector<HTMLInputElement>('#email')
const errorBox = document.querySelector<HTMLElement>('#password-error')

if (!form || !passwordInput || !errorBox) {
  throw new Error('Registration form elements are missing')
}

const blocklist = await PasswordBlocklist.fromUrl('/passwords/frontend-blocklist.txt')
const policy = new PasswordPolicy({
  blocklist,
  contextChecker: new ContextPasswordChecker(['examplecorp', 'example-product']),
  strengthEstimator: new ZxcvbnTsStrengthEstimator(),
  pwnedChecker: new HibpPwnedPasswordClient({ timeoutMs: 5_000 }),
})

form.addEventListener('submit', async (event) => {
  event.preventDefault()
  errorBox.textContent = ''

  const result = await policy.assess(passwordInput.value, {
    mfaProtected: false,
    context: {
      ...(usernameInput ? { username: usernameInput.value } : {}),
      ...(emailInput ? { email: emailInput.value } : {}),
      serviceName: 'example-product',
    },
  })

  if (!result.accepted) {
    errorBox.textContent = result.violations[0]?.message ?? '密码不符合要求。'
    return
  }

  // Submit to your backend. The backend must run the same checks again.
  form.submit()
})
