  /* Sign-in screen: reveal the password field on demand. */
  const passwordToggle = document.querySelector('[data-password-toggle]');
  if (passwordToggle) {
    const passwordField = document.getElementById('login-password');
    const setPasswordVisible = visible => {
      passwordField.type = visible ? 'text' : 'password';
      passwordToggle.classList.toggle('is-visible', visible);
      passwordToggle.setAttribute('aria-pressed', String(visible));
      passwordToggle.setAttribute('aria-label', visible ? '隐藏密码' : '显示密码');
    };
    passwordToggle.addEventListener('click', () => setPasswordVisible(passwordField.type === 'password'));
    setPasswordVisible(false);
  }

  /* Decorative stars: only mounted on login; CSS drives the animation. */
  const starfield = document.querySelector('.login-starfield');
  if (starfield) {
    const fragment = document.createDocumentFragment();
    // Stable distribution avoids a visual jump on validation errors/reloads.
    let seed = 127;
    const random = () => {
      seed = (seed * 16807) % 2147483647;
      return (seed - 1) / 2147483646;
    };
    for (let index = 0; index < 112; index++) {
      const particle = document.createElement('span');
      const star = index % 9 === 0;
      particle.className = 'login-particle' + (star ? ' is-star' : index % 5 === 0 ? ' is-glow' : '');
      const properties = {
        '--x': (3 + random() * 94) + '%',
        '--y': (2 + random() * 96) + '%',
        '--size': (star ? 7 + random() * 7 : 1 + random() * 2) + 'px',
        '--drift': (14 + random() * 22) + 's',
        '--twinkle': (3 + random() * 5) + 's',
        '--delay': (-random() * 36) + 's',
        '--shift': (-14 + random() * 28) + 'px'
      };
      Object.entries(properties).forEach(([key, value]) => particle.style.setProperty(key, value));
      particle.appendChild(document.createElement('i'));
      fragment.appendChild(particle);
    }
    starfield.appendChild(fragment);
    const syncStarVisibility = () => starfield.parentElement.classList.toggle('is-paused', document.hidden);
    document.addEventListener('visibilitychange', syncStarVisibility);
    syncStarVisibility();
  }
