"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const tabs = [$("host-tab"), $("pem-tab")];
  let mode = "host";
  let currentPEM = "";
  let currentHostLink = "";
  let requestVersion = 0;
  let activeController = null;
  const privateKey = /-----BEGIN[\w\s-]*PRIVATE KEY-----/i;
  function normalizeHost(value) {
    const input = value.trim();
    if (!input || /[\s/\\?#@%]/u.test(input)) throw new Error("invalid host");
    // Parse the port separately: URL.port drops an explicit default port.
    const parts = input.startsWith("[")
      ? input.match(/^(\[[^\]]+\])(?::([0-9]+))?$/u)
      : input.match(/^([^:]+)(?::([0-9]+))?$/u);
    if (!parts) throw new Error("invalid host");
    const [, hostname, port] = parts;
    if (port && (Number(port) < 1 || Number(port) > 65535))
      throw new Error("invalid port");
    // The browser implements IDNA, including Unicode → ASCII/punycode conversion.
    const ascii = new URL(`https://${hostname}${port ? `:${port}` : ""}`)
      .hostname;
    if (!ascii.startsWith("[")) {
      const domain = ascii.endsWith(".") ? ascii.slice(0, -1) : ascii;
      if (
        domain.length > 253 ||
        !domain
          .split(".")
          .every((label) =>
            /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label),
          )
      ) {
        throw new Error("invalid hostname");
      }
    }
    return `${ascii}${port ? `:${port}` : ""}`;
  }
  function selectMode(index) {
    const nextMode = index === 0 ? "host" : "pem";
    if (nextMode !== mode) resetOutput();
    mode = nextMode;
    tabs.forEach((tab, i) => {
      tab.classList.toggle("active", i === index);
      tab.setAttribute("aria-selected", String(i === index));
      tab.tabIndex = i === index ? 0 : -1;
    });
    $("host-panel").hidden = index !== 0;
    $("pem-panel").hidden = index !== 1;
    $("host").disabled = index !== 0;
    $("host").required = index === 0;
    $("cert-pem").disabled = index !== 1;
    $("cert-pem").required = index === 1;
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => selectMode(index));
    tab.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key))
        return;
      event.preventDefault();
      const next =
        event.key === "Home" ? 0 : event.key === "End" ? 1 : 1 - index;
      selectMode(next);
      tabs[next].focus();
    });
  });
  function showResult(status, message, errorKind = "input") {
    const known = ["ok", "warning", "error"].includes(status)
      ? status
      : "error";
    $("result").hidden = false;
    $("result").dataset.status = known;
    $("result-symbol").hidden = false;
    for (const state of ["ok", "warning", "error"]) {
      $("symbol-" + state).toggleAttribute("hidden", state !== known);
    }
    $("result-title").textContent = {
      ok: "Цепочка действительна",
      warning: "В цепочке есть замечания",
      error:
        errorKind === "certificate"
          ? "Цепочка не прошла проверку"
          : errorKind === "request"
            ? "Не удалось выполнить проверку"
            : "Проверьте введённые данные",
    }[known];
    $("result-message").textContent =
      message || "Сервер не вернул описание результата.";
    $("result-title").focus({ preventScroll: true });
    $("result").scrollIntoView({
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches
        ? "instant"
        : "smooth",
      block: "start",
    });
  }
  function resetOutput() {
    requestVersion++;
    activeController?.abort();
    activeController = null;
    $("submit").disabled = false;
    $("submit-label").textContent = "Проверить цепочку";
    $("check-form").removeAttribute("aria-busy");
    $("result").hidden = true;
    $("result").removeAttribute("data-status");
    $("result-symbol").hidden = true;
    currentPEM = "";
    currentHostLink = "";
    $("share-result").hidden = true;
    $("share-fallback").hidden = true;
    $("share-url").value = "";
    $("share-status").textContent = "";
    for (const id of [
      "presented-section",
      "chain-section",
      "pem-section",
      "issues",
    ])
      $(id).hidden = true;
    $("presented-chain").replaceChildren();
    $("reconstructed-chain").replaceChildren();
    $("issues").replaceChildren();
    $("pem-output").textContent = "";
    $("copy-pem").textContent = "Скопировать";
    $("chain-choice").hidden = true;
    $("chain-options").replaceChildren();
    $("chain-label").textContent = "Собранная цепочка";
  }
  function selectPEM(pem) {
    currentPEM = pem;
    $("pem-output").textContent = pem;
    $("copy-pem").textContent = "Скопировать";
  }
  function renderPEMChoices(data) {
    selectPEM(data.pem);
    $("pem-section").hidden = false;
    const alternatives = [];
    const seen = new Set([data.pem]);
    for (const item of Array.isArray(data.compatibilityChains)
      ? data.compatibilityChains
      : []) {
      if (
        data.status === "error" ||
        typeof item.pem !== "string" ||
        !item.pem.trim() ||
        privateKey.test(item.pem) ||
        seen.has(item.pem)
      )
        continue;
      seen.add(item.pem);
      alternatives.push(item);
    }
    if (!alternatives.length) return;
    $("chain-choice").hidden = false;
    $("chain-label").textContent = "Короткая цепочка";
    const bundles = [
      { label: "Короткая цепочка", pem: data.pem },
      ...alternatives.map((item) => ({
        label: `Для совместимости — ${typeof item.root === "string" && item.root.trim() ? item.root : "другой доверенный корень"}`,
        pem: item.pem,
      })),
    ];
    bundles.forEach((bundle, index) => {
      const label = document.createElement("label");
      label.className = "chain-option";
      const radio = document.createElement("input");
      radio.type = "radio";
      radio.name = "pem-chain";
      radio.value = String(index);
      radio.checked = index === 0;
      radio.addEventListener("change", () => {
        if (radio.checked) selectPEM(bundle.pem);
      });
      const text = document.createElement("span");
      text.textContent = bundle.label;
      label.append(radio, text);
      $("chain-options").append(label);
    });
  }
  function renderChain(items, target, section, count) {
    if (!Array.isArray(items) || !items.length) return;
    $(section).hidden = false;
    $(count).textContent = `(${items.length})`;
    items.forEach((cert) => {
      const li = document.createElement("li");
      const content = document.createElement("div");
      const add = (text, className) => {
        const span = document.createElement("span");
        span.className = className;
        span.textContent = text;
        content.append(span);
      };
      add(cert.subject || "Имя не указано", "cert-subject");
      add(`Издатель: ${cert.issuer || "не указан"}`, "cert-detail");
      if (cert.notAfter) {
        const date = new Date(cert.notAfter);
        add(
          `Действует до: ${Number.isNaN(date.getTime()) ? cert.notAfter : new Intl.DateTimeFormat("ru-RU", { dateStyle: "long", timeStyle: "short" }).format(date)}`,
          "cert-detail",
        );
      }
      if (cert.sha256) add(`SHA-256: ${cert.sha256}`, "cert-detail cert-hash");
      li.append(content);
      $(target).append(li);
    });
  }
  $("check-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    resetOutput();
    const version = requestVersion;
    // Check both fields before any request, including an inactive field.
    if (
      privateKey.test($("cert-pem").value) ||
      privateKey.test($("host").value)
    ) {
      showResult(
        "error",
        "В поле обнаружен приватный ключ. Удалите его: для проверки нужен только публичный сертификат. Данные не отправлены.",
      );
      return;
    }
    const submittedMode = mode;
    let host = "";
    const certPEM = mode === "pem" ? $("cert-pem").value.trim() : "";
    if (mode === "host") {
      try {
        host = normalizeHost($("host").value);
      } catch {
        showResult(
          "error",
          "Введите имя хоста без протокола, пути и пробелов, например пример.рф или example.com:8443. Порт — число от 1 до 65535.",
        );
        return;
      }
    }
    if (
      mode === "pem" &&
      !/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.test(
        certPEM,
      )
    ) {
      showResult(
        "error",
        "Вставьте публичный сертификат между строками BEGIN CERTIFICATE и END CERTIFICATE.",
      );
      return;
    }
    $("submit").disabled = true;
    $("submit-label").textContent = "Проверяем цепочку…";
    $("check-form").setAttribute("aria-busy", "true");
    const controller = new AbortController();
    activeController = controller;
    const timeout = setTimeout(() => controller.abort(), 60000);
    try {
      const response = await fetch("/api/check", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          host,
          certPEM,
          includeRoot: $("include-root").checked,
        }),
        signal: controller.signal,
      });
      let data;
      try {
        data = await response.json();
      } catch {
        throw new Error(
          "Сервер вернул неожиданный ответ. Повторите проверку позже.",
        );
      }
      if (version !== requestVersion) return;
      if (!response.ok)
        throw new Error(
          data.message ||
            `Ошибка сервера (${response.status}). Повторите проверку позже.`,
        );
      if (
        !data ||
        typeof data !== "object" ||
        !["ok", "warning", "error"].includes(data.status)
      )
        throw new Error(
          "Сервер вернул неожиданный результат. Повторите проверку позже.",
        );
      const certificateResult =
        Array.isArray(data.presented) &&
        data.presented.length > 0 &&
        !data.issues?.some((issue) => issue.code === "canceled");
      showResult(
        data.status,
        data.message,
        certificateResult ? "certificate" : "request",
      );
      if (submittedMode === "host") {
        const link = new URL("/", window.location.origin);
        link.searchParams.set("host", host);
        currentHostLink = link.href;
        $("share-result").hidden = false;
      }
      $("presented-label").textContent =
        submittedMode === "host" ? "Сервер передал" : "Переданные сертификаты";
      renderChain(
        data.presented,
        "presented-chain",
        "presented-section",
        "presented-count",
      );
      renderChain(
        data.chain,
        "reconstructed-chain",
        "chain-section",
        "chain-count",
      );
      if (Array.isArray(data.issues) && data.issues.length) {
        $("issues").hidden = false;
        data.issues.forEach((issue) => {
          const li = document.createElement("li");
          const severity = ["info", "warning", "error"].includes(issue.severity)
            ? issue.severity
            : "warning";
          li.className = `issue issue-${severity}`;
          const label = document.createElement("strong");
          label.className = "issue-label";
          label.textContent = {
            info: "Информация",
            warning: "Предупреждение",
            error: "Ошибка",
          }[severity];
          const message = document.createElement("span");
          message.textContent =
            issue.message || issue.code || "Сообщение о цепочке сертификатов.";
          li.append(label, message);
          $("issues").append(li);
        });
      }
      if (
        typeof data.pem === "string" &&
        data.pem.trim() &&
        !privateKey.test(data.pem)
      ) {
        renderPEMChoices(data);
      }
    } catch (error) {
      if (version !== requestVersion) return;
      showResult(
        "error",
        error.name === "AbortError"
          ? "Сервер не ответил за минуту. Повторите проверку или вставьте сертификат в PEM."
          : error instanceof TypeError
            ? "Не удалось связаться с сервером. Проверьте соединение и повторите попытку."
            : error.message,
        "request",
      );
    } finally {
      clearTimeout(timeout);
      if (version === requestVersion) {
        activeController = null;
        $("submit").disabled = false;
        $("submit-label").textContent = "Проверить цепочку";
        $("check-form").removeAttribute("aria-busy");
      }
    }
  });
  $("copy-pem").addEventListener("click", async () => {
    const pem = currentPEM;
    if (!pem) return;
    try {
      await navigator.clipboard.writeText(pem);
      if (currentPEM === pem) $("copy-pem").textContent = "Скопировано ✓";
    } catch {
      if (currentPEM !== pem) return;
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents($("pem-output"));
      selection.removeAllRanges();
      selection.addRange(range);
      $("pem-output").focus();
      $("copy-pem").textContent = "Нажмите Ctrl/Cmd+C";
    }
  });
  $("download-pem").addEventListener("click", () => {
    if (!currentPEM) return;
    const url = URL.createObjectURL(
      new Blob([currentPEM], { type: "application/x-pem-file" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = "fullchain.pem";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  $("copy-link").addEventListener("click", async () => {
    const link = currentHostLink;
    if (!link) return;
    try {
      await navigator.clipboard.writeText(link);
      if (currentHostLink === link) {
        $("share-status").textContent = "Ссылка скопирована.";
      }
    } catch {
      if (currentHostLink !== link) return;
      $("share-fallback").hidden = false;
      $("share-url").value = link;
      $("share-url").focus();
      $("share-url").select();
      $("share-status").textContent =
        "Скопируйте выделенную ссылку: Ctrl+C или Cmd+C.";
    }
  });

  // Deep links contain only a hostname. PEM and key material are never read from URLs.
  const params = new URLSearchParams(window.location.search);
  const hosts = params.getAll("host");
  if (hosts.length) {
    if (hosts.length !== 1) {
      showResult(
        "error",
        "В ссылке должен быть один параметр host с адресом сервера. Проверка не запущена.",
      );
    } else {
      try {
        normalizeHost(hosts[0]);
        $("host").value = hosts[0];
        $("check-form").requestSubmit();
      } catch {
        showResult(
          "error",
          "В ссылке указан некорректный адрес сервера. Используйте имя хоста и, при необходимости, порт от 1 до 65535. Проверка не запущена.",
        );
      }
    }
  }
})();
