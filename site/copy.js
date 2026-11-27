// The only script on the page: copy the install command. Served from this origin (the CSP allows nothing else).
const button = document.getElementById('copy')
const cmd = document.getElementById('cmd')
if (button && cmd && navigator.clipboard) {
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(cmd.textContent)
      button.textContent = 'Copied'
    } catch {
      button.textContent = 'Select and copy'
    }
    setTimeout(() => { button.textContent = 'Copy' }, 2000)
  })
} else if (button) {
  button.hidden = true
}
