window.__R19_ENH = function () {
  // Disable submit after click
  document.querySelectorAll('form').forEach(f => {
    f.addEventListener('submit', () => {
      const btn = f.querySelector('button[type="submit"]');
      if (btn) { btn.disabled = true; btn.innerText = 'Submitting…'; }
    });
  });

  // Description counter
  const desc = document.getElementById('description');
  const counter = document.getElementById('desc-counter');
  if (desc && counter) {
    const update = () => {
      counter.textContent = `${desc.value.length} / ${desc.maxLength}`;
    };
    desc.addEventListener('input', update);
    update();
  }

  // Simple dropzone preview
  const dz = document.getElementById('r19-dropzone');
  const fileInput = document.getElementById('screenshot');
  const pickBtn = document.getElementById('pick-file');
  const previewWrap = document.getElementById('dz-preview');
  const previewImg = document.getElementById('dz-image');

  const showPreview = (file) => {
    if (!file || !file.type.startsWith('image/')) return;
    const url = URL.createObjectURL(file);
    previewImg.src = url;
    if (previewWrap) previewWrap.classList.remove('d-none');
  };

  if (pickBtn && fileInput) {
    pickBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
      const [file] = e.target.files || [];
      showPreview(file);
    });
  }

  if (dz && fileInput) {
    const stop = (e) => { e.preventDefault(); e.stopPropagation(); };
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(evt => dz.addEventListener(evt, stop));
    ['dragenter', 'dragover'].forEach(evt => dz.addEventListener(evt, () => dz.classList.add('dragover')));
    ['dragleave', 'drop'].forEach(evt => dz.addEventListener(evt, () => dz.classList.remove('dragover')));
    dz.addEventListener('drop', (e) => {
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (!file) return;
      if (!file.type.startsWith('image/')) return;
      // Attach to input for form submission
      const dt = new DataTransfer();
      dt.items.add(file);
      fileInput.files = dt.files;
      showPreview(file);
    });
  }
};
