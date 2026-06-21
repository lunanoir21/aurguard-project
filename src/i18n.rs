//! Internationalization: the [`Lang`] enum and message catalogs for English,
//! Turkish, French, Spanish, and Azerbaijani.
//!
//! UI chrome (panel labels, prompts, the setup wizard, suggestion list) is
//! localized via [`t`] keyed by [`K`]. Finding descriptions are localized via
//! [`finding`] keyed by the finding's stable `code`; templates may contain a
//! single `{}` placeholder filled with the finding's dynamic detail. Anything
//! without a translation falls back to English.

use serde::Deserialize;

/// Supported interface languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    /// English (default).
    #[default]
    En,
    /// Turkish.
    Tr,
    /// French.
    Fr,
    /// Spanish.
    Es,
    /// Azerbaijani.
    Az,
}

impl Lang {
    /// Every language, in wizard display order.
    pub const ALL: [Lang; 5] = [Lang::En, Lang::Tr, Lang::Fr, Lang::Es, Lang::Az];

    /// ISO-ish short code (`"en"`, `"tr"`, …).
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Tr => "tr",
            Lang::Fr => "fr",
            Lang::Es => "es",
            Lang::Az => "az",
        }
    }

    /// Endonym shown in the wizard (e.g. `"Türkçe"`).
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Tr => "Türkçe",
            Lang::Fr => "Français",
            Lang::Es => "Español",
            Lang::Az => "Azərbaycan",
        }
    }
}

impl std::str::FromStr for Lang {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "en" | "english" => Ok(Lang::En),
            "tr" | "türkçe" | "turkce" | "turkish" => Ok(Lang::Tr),
            "fr" | "français" | "francais" | "french" => Ok(Lang::Fr),
            "es" | "español" | "espanol" | "spanish" => Ok(Lang::Es),
            "az" | "azərbaycan" | "azerbaijani" | "azeri" => Ok(Lang::Az),
            other => anyhow::bail!("unknown language '{other}' (en|tr|fr|es|az)"),
        }
    }
}

/// UI message keys.
#[derive(Debug, Clone, Copy)]
pub enum K {
    ReportTitle,
    LabelPackage,
    LabelMaintainer,
    LabelVotes,
    LabelLastUpdate,
    LabelSources,
    LabelFindings,
    NoneDetected,
    Orphaned,
    LocalFile,
    NoneDeclared,
    PromptInstall,
    PromptRisky,
    PromptCritical,
    Installed,
    Fetching,
    Cloning,
    SuggestHeader,
    SuggestSelect,
    SuggestRerun,
    SuggestVotes,
    SuggestOutOfDate,
    WizTitle,
    WizLangQ,
    WizPolicyQ,
    WizPolicyClean,
    WizPolicyRisky,
    WizPolicyCritical,
    WizColorQ,
    WizDomainsQ,
    WizSaved,
    WizCancelled,
    YesNoSuffix,
    Today,
    Future,
    DayAgo,
    DaysAgo,
    MonthAgo,
    MonthsAgo,
    YearAgo,
    YearsAgo,
    Since,
    SinceYear,
}

/// Localized UI string for `key`. Some carry a single `{}` placeholder.
pub fn t(lang: Lang, key: K) -> &'static str {
    use Lang::*;
    use K::*;
    match key {
        ReportTitle => match lang {
            En => "aurguard — Security Report",
            Tr => "aurguard — Güvenlik Raporu",
            Fr => "aurguard — Rapport de sécurité",
            Es => "aurguard — Informe de seguridad",
            Az => "aurguard — Təhlükəsizlik hesabatı",
        },
        LabelPackage => match lang {
            En => "Package",
            Tr => "Paket",
            Fr => "Paquet",
            Es => "Paquete",
            Az => "Paket",
        },
        LabelMaintainer => match lang {
            En => "Maintainer",
            Tr => "Bakımcı",
            Fr => "Mainteneur",
            Es => "Mantenedor",
            Az => "Təminatçı",
        },
        LabelVotes => match lang {
            En => "Votes",
            Tr => "Oylar",
            Fr => "Votes",
            Es => "Votos",
            Az => "Səslər",
        },
        LabelLastUpdate => match lang {
            En => "Last update",
            Tr => "Son güncelleme",
            Fr => "Mise à jour",
            Es => "Actualizado",
            Az => "Son yeniləmə",
        },
        LabelSources => match lang {
            En => "Sources",
            Tr => "Kaynaklar",
            Fr => "Sources",
            Es => "Fuentes",
            Az => "Mənbələr",
        },
        LabelFindings => match lang {
            En => "Findings",
            Tr => "Bulgular",
            Fr => "Constats",
            Es => "Hallazgos",
            Az => "Tapıntılar",
        },
        NoneDetected => match lang {
            En => "None detected",
            Tr => "Tespit edilmedi",
            Fr => "Aucun détecté",
            Es => "Ninguno detectado",
            Az => "Aşkar edilmədi",
        },
        Orphaned => match lang {
            En => "orphaned",
            Tr => "sahipsiz",
            Fr => "orphelin",
            Es => "huérfano",
            Az => "yiyəsiz",
        },
        LocalFile => match lang {
            En => "— (local file)",
            Tr => "— (yerel dosya)",
            Fr => "— (fichier local)",
            Es => "— (archivo local)",
            Az => "— (yerli fayl)",
        },
        NoneDeclared => match lang {
            En => "none declared",
            Tr => "belirtilmemiş",
            Fr => "aucune déclarée",
            Es => "ninguna declarada",
            Az => "bəyan edilməyib",
        },
        PromptInstall => match lang {
            En => "Install {}? [y/N] ",
            Tr => "{} kurulsun mu? [e/H] ",
            Fr => "Installer {} ? [o/N] ",
            Es => "¿Instalar {}? [s/N] ",
            Az => "{} quraşdırılsın? [b/X] ",
        },
        PromptRisky => match lang {
            En => "This package has security risks. Install anyway? [y/N] ",
            Tr => "Bu paketin güvenlik riskleri var. Yine de kurulsun mu? [e/H] ",
            Fr => "Ce paquet présente des risques. Installer quand même ? [o/N] ",
            Es => "Este paquete tiene riesgos. ¿Instalar de todos modos? [s/N] ",
            Az => "Bu paketdə təhlükəsizlik riskləri var. Yenə də quraşdırılsın? [b/X] ",
        },
        PromptCritical => match lang {
            En => "Critical risks detected. Install anyway? [y/N] ",
            Tr => "Kritik riskler tespit edildi. Yine de kurulsun mu? [e/H] ",
            Fr => "Risques critiques détectés. Installer quand même ? [o/N] ",
            Es => "Riesgos críticos detectados. ¿Instalar de todos modos? [s/N] ",
            Az => "Kritik risklər aşkarlandı. Yenə də quraşdırılsın? [b/X] ",
        },
        Installed => match lang {
            En => "{} installed successfully",
            Tr => "{} başarıyla kuruldu",
            Fr => "{} installé avec succès",
            Es => "{} instalado correctamente",
            Az => "{} uğurla quraşdırıldı",
        },
        Fetching => match lang {
            En => "Fetching {}…",
            Tr => "{} getiriliyor…",
            Fr => "Récupération de {}…",
            Es => "Obteniendo {}…",
            Az => "{} alınır…",
        },
        Cloning => match lang {
            En => "Cloning {}…",
            Tr => "{} klonlanıyor…",
            Fr => "Clonage de {}…",
            Es => "Clonando {}…",
            Az => "{} klonlanır…",
        },
        SuggestHeader => match lang {
            En => "No exact match for '{}'. Similar packages on the AUR:",
            Tr => "'{}' için tam eşleşme yok. AUR'daki benzer paketler:",
            Fr => "Aucune correspondance exacte pour « {} ». Paquets similaires sur l'AUR :",
            Es => "Sin coincidencia exacta para «{}». Paquetes similares en la AUR:",
            Az => "'{}' üçün dəqiq uyğunluq yoxdur. AUR-da oxşar paketlər:",
        },
        SuggestSelect => match lang {
            En => "Select a package to use [1-{}], or Enter to cancel: ",
            Tr => "Kullanılacak paketi seçin [1-{}], iptal için Enter: ",
            Fr => "Choisissez un paquet [1-{}], ou Entrée pour annuler : ",
            Es => "Elija un paquete [1-{}], o Enter para cancelar: ",
            Az => "İstifadə üçün paket seçin [1-{}], ləğv üçün Enter: ",
        },
        SuggestRerun => match lang {
            En => "Re-run with an exact name, e.g. `aurguard -S {}`.",
            Tr => "Tam adla tekrar çalıştırın, ör. `aurguard -S {}`.",
            Fr => "Relancez avec un nom exact, p. ex. `aurguard -S {}`.",
            Es => "Vuelva a ejecutar con un nombre exacto, p. ej. `aurguard -S {}`.",
            Az => "Dəqiq adla yenidən işlədin, məs. `aurguard -S {}`.",
        },
        SuggestVotes => match lang {
            En => "votes",
            Tr => "oy",
            Fr => "votes",
            Es => "votos",
            Az => "səs",
        },
        SuggestOutOfDate => match lang {
            En => " (out of date)",
            Tr => " (güncel değil)",
            Fr => " (obsolète)",
            Es => " (desactualizado)",
            Az => " (köhnəlmiş)",
        },
        WizTitle => match lang {
            En => "aurguard setup",
            Tr => "aurguard kurulum",
            Fr => "configuration aurguard",
            Es => "configuración de aurguard",
            Az => "aurguard quraşdırma",
        },
        WizLangQ => match lang {
            En => "Interface language",
            Tr => "Arayüz dili",
            Fr => "Langue de l'interface",
            Es => "Idioma de la interfaz",
            Az => "İnterfeys dili",
        },
        WizPolicyQ => match lang {
            En => "Block non-interactive installs at which risk?",
            Tr => "Etkileşimsiz kurulumlar hangi riskte engellensin?",
            Fr => "Bloquer les installations non interactives à quel risque ?",
            Es => "¿Bloquear instalaciones no interactivas en qué riesgo?",
            Az => "Qeyri-interaktiv quraşdırmalar hansı riskdə bloklansın?",
        },
        WizPolicyClean => match lang {
            En => "any finding (clean)",
            Tr => "herhangi bir bulgu (clean)",
            Fr => "tout constat (clean)",
            Es => "cualquier hallazgo (clean)",
            Az => "istənilən tapıntı (clean)",
        },
        WizPolicyRisky => match lang {
            En => "risky or worse",
            Tr => "riskli ve üzeri",
            Fr => "risqué ou pire",
            Es => "riesgoso o peor",
            Az => "riskli və ya daha pis",
        },
        WizPolicyCritical => match lang {
            En => "critical only (recommended)",
            Tr => "yalnızca kritik (önerilen)",
            Fr => "critique seulement (recommandé)",
            Es => "solo crítico (recomendado)",
            Az => "yalnız kritik (tövsiyə olunan)",
        },
        WizColorQ => match lang {
            En => "Enable colored output?",
            Tr => "Renkli çıktı etkin olsun mu?",
            Fr => "Activer la sortie en couleur ?",
            Es => "¿Habilitar salida en color?",
            Az => "Rəngli çıxış aktiv olsun?",
        },
        WizDomainsQ => match lang {
            En => "Extra trusted domains (comma-separated, blank for none)",
            Tr => "Ek güvenilen alan adları (virgülle, yoksa boş bırakın)",
            Fr => "Domaines de confiance supplémentaires (séparés par des virgules)",
            Es => "Dominios de confianza adicionales (separados por comas)",
            Az => "Əlavə etibarlı domenlər (vergüllə, yoxdursa boş)",
        },
        WizSaved => match lang {
            En => "Configuration saved to {}",
            Tr => "Yapılandırma kaydedildi: {}",
            Fr => "Configuration enregistrée dans {}",
            Es => "Configuración guardada en {}",
            Az => "Konfiqurasiya saxlanıldı: {}",
        },
        WizCancelled => match lang {
            En => "Setup cancelled.",
            Tr => "Kurulum iptal edildi.",
            Fr => "Configuration annulée.",
            Es => "Configuración cancelada.",
            Az => "Quraşdırma ləğv edildi.",
        },
        YesNoSuffix => match lang {
            En => "[Y/n] ",
            Tr => "[E/h] ",
            Fr => "[O/n] ",
            Es => "[S/n] ",
            Az => "[B/x] ",
        },
        Today => match lang {
            En => "today",
            Tr => "bugün",
            Fr => "aujourd'hui",
            Es => "hoy",
            Az => "bu gün",
        },
        Future => match lang {
            En => "in the future",
            Tr => "gelecekte",
            Fr => "dans le futur",
            Es => "en el futuro",
            Az => "gələcəkdə",
        },
        DayAgo => match lang {
            En => "1 day ago",
            Tr => "1 gün önce",
            Fr => "il y a 1 jour",
            Es => "hace 1 día",
            Az => "1 gün əvvəl",
        },
        DaysAgo => match lang {
            En => "{} days ago",
            Tr => "{} gün önce",
            Fr => "il y a {} jours",
            Es => "hace {} días",
            Az => "{} gün əvvəl",
        },
        MonthAgo => match lang {
            En => "1 month ago",
            Tr => "1 ay önce",
            Fr => "il y a 1 mois",
            Es => "hace 1 mes",
            Az => "1 ay əvvəl",
        },
        MonthsAgo => match lang {
            En => "{} months ago",
            Tr => "{} ay önce",
            Fr => "il y a {} mois",
            Es => "hace {} meses",
            Az => "{} ay əvvəl",
        },
        YearAgo => match lang {
            En => "1 year ago",
            Tr => "1 yıl önce",
            Fr => "il y a 1 an",
            Es => "hace 1 año",
            Az => "1 il əvvəl",
        },
        YearsAgo => match lang {
            En => "{} years ago",
            Tr => "{} yıl önce",
            Fr => "il y a {} ans",
            Es => "hace {} años",
            Az => "{} il əvvəl",
        },
        Since => match lang {
            En => "since {}",
            Tr => "{} beri",
            Fr => "depuis {}",
            Es => "desde {}",
            Az => "{} bəri",
        },
        SinceYear => match lang {
            En => "since {}",
            Tr => "{} yılından beri",
            Fr => "depuis {}",
            Es => "desde {}",
            Az => "{}-ci ildən bəri",
        },
    }
}

/// Localized template for a finding `code`. `{}` (if present) is filled with
/// the finding's dynamic detail. `None` → caller keeps the English message.
pub fn finding(lang: Lang, code: &str) -> Option<&'static str> {
    use Lang::*;
    let s = match code {
        "EVAL" => match lang {
            En => "Use of `eval` (dynamic code execution)",
            Tr => "`eval` kullanımı (dinamik kod çalıştırma)",
            Fr => "Utilisation de `eval` (exécution de code dynamique)",
            Es => "Uso de `eval` (ejecución dinámica de código)",
            Az => "`eval` istifadəsi (dinamik kod icrası)",
        },
        "CURL_PIPE_SH" => match lang {
            En => "Remote script piped directly into a shell",
            Tr => "Uzak betik doğrudan kabuğa boru ile aktarılıyor",
            Fr => "Script distant redirigé directement vers un shell",
            Es => "Script remoto canalizado directamente a un shell",
            Az => "Uzaq skript birbaşa shell-ə yönləndirilir",
        },
        "BASE64_PIPE_SH" => match lang {
            En => "Decoded payload piped into a shell",
            Tr => "Çözülmüş yük kabuğa boru ile aktarılıyor",
            Fr => "Charge décodée redirigée vers un shell",
            Es => "Carga decodificada canalizada a un shell",
            Az => "Dekodlanmış yük shell-ə yönləndirilir",
        },
        "DOWNLOAD_EXEC" => match lang {
            En => "Downloaded file executed (fetch-then-run)",
            Tr => "İndirilen dosya çalıştırılıyor (indir-sonra-çalıştır)",
            Fr => "Fichier téléchargé exécuté (télécharger puis exécuter)",
            Es => "Archivo descargado ejecutado (descargar y ejecutar)",
            Az => "Yüklənmiş fayl icra olunur (yüklə-sonra-işlət)",
        },
        "INSECURE_SOURCE" => match lang {
            En => "Insecure source URL: {}",
            Tr => "Güvensiz kaynak URL: {}",
            Fr => "URL source non sécurisée : {}",
            Es => "URL de origen insegura: {}",
            Az => "Təhlükəsiz olmayan mənbə URL: {}",
        },
        "IP_SOURCE" => match lang {
            En => "Source points at a raw IP address: {}",
            Tr => "Kaynak çıplak bir IP adresini gösteriyor: {}",
            Fr => "La source pointe vers une adresse IP brute : {}",
            Es => "La fuente apunta a una IP directa: {}",
            Az => "Mənbə birbaşa IP ünvanına işarə edir: {}",
        },
        "CHMOD_EXEC" => match lang {
            En => "File made executable and run immediately",
            Tr => "Dosya çalıştırılabilir yapılıp hemen çalıştırılıyor",
            Fr => "Fichier rendu exécutable puis lancé aussitôt",
            Es => "Archivo hecho ejecutable y ejecutado de inmediato",
            Az => "Fayl icra edilə bilən edilir və dərhal işlədilir",
        },
        "UNKNOWN_SOURCE" => match lang {
            En => "Unknown source domain: {}",
            Tr => "Bilinmeyen kaynak alan adı: {}",
            Fr => "Domaine source inconnu : {}",
            Es => "Dominio de origen desconocido: {}",
            Az => "Naməlum mənbə domeni: {}",
        },
        "CHECKSUM_SKIP" => match lang {
            En => "Checksum set to SKIP for a downloaded source (integrity unverified)",
            Tr => "İndirilen kaynak için sağlama SKIP (bütünlük doğrulanmıyor)",
            Fr => "Somme de contrôle SKIP pour une source téléchargée (intégrité non vérifiée)",
            Es => {
                "Suma de verificación en SKIP para una fuente descargada (integridad sin verificar)"
            }
            Az => "Yüklənən mənbə üçün yoxlama cəmi SKIP (bütövlük yoxlanılmır)",
        },
        "INSTALL_HOOK" => match lang {
            En => "Package ships an install scriptlet (runs as root on install)",
            Tr => "Paket bir install betiği içeriyor (kurulumda root olarak çalışır)",
            Fr => "Le paquet inclut un script d'installation (exécuté en root)",
            Es => "El paquete incluye un script de instalación (se ejecuta como root)",
            Az => "Paket install skripti daşıyır (quraşdırmada root kimi işləyir)",
        },
        "INSTALL_NETWORK" => match lang {
            En => "Network access from an install scriptlet ({})",
            Tr => "Install betiğinden ağ erişimi ({})",
            Fr => "Accès réseau depuis un script d'installation ({})",
            Es => "Acceso a red desde un script de instalación ({})",
            Az => "Install skriptindən şəbəkə girişi ({})",
        },
        "TMP_EXEC" => match lang {
            En => "Executes a file staged in /tmp",
            Tr => "/tmp'de hazırlanan bir dosyayı çalıştırıyor",
            Fr => "Exécute un fichier déposé dans /tmp",
            Es => "Ejecuta un archivo preparado en /tmp",
            Az => "/tmp-də hazırlanan faylı işlədir",
        },
        "GIT_CLONE_UNKNOWN" => match lang {
            En => "git clone of an untrusted repo: {}",
            Tr => "Güvenilmeyen depodan git clone: {}",
            Fr => "git clone d'un dépôt non fiable : {}",
            Es => "git clone de un repositorio no confiable: {}",
            Az => "Etibarsız repodan git clone: {}",
        },
        "PKGBUILD_CHANGED" => match lang {
            En => "PKGBUILD changed since you last approved this package",
            Tr => "Bu paketi son onayladığınızdan beri PKGBUILD değişti",
            Fr => "Le PKGBUILD a changé depuis votre dernière approbation",
            Es => "El PKGBUILD cambió desde su última aprobación",
            Az => "Bu paketi son təsdiqlədiyinizdən bəri PKGBUILD dəyişib",
        },
        "NEW_MAINTAINER" => match lang {
            En => "Young package/maintainer ({})",
            Tr => "Genç paket/bakımcı ({})",
            Fr => "Paquet/mainteneur récent ({})",
            Es => "Paquete/mantenedor reciente ({})",
            Az => "Gənc paket/təminatçı ({})",
        },
        "LOW_VOTES" => match lang {
            En => "Low community trust ({} votes)",
            Tr => "Düşük topluluk güveni ({} oy)",
            Fr => "Faible confiance de la communauté ({} votes)",
            Es => "Baja confianza de la comunidad ({} votos)",
            Az => "Aşağı icma etimadı ({} səs)",
        },
        "STALE" => match lang {
            En => "Last updated {}",
            Tr => "Son güncelleme {}",
            Fr => "Dernière mise à jour {}",
            Es => "Última actualización {}",
            Az => "Son yeniləmə {}",
        },
        "PKGREL_CHURN" => match lang {
            En => "High pkgrel ({}) — many rebuilds on the same version",
            Tr => "Yüksek pkgrel ({}) — aynı sürümde çok sayıda yeniden derleme",
            Fr => "pkgrel élevé ({}) — nombreuses reconstructions",
            Es => "pkgrel alto ({}) — muchas recompilaciones",
            Az => "Yüksək pkgrel ({}) — eyni versiyada çoxlu yenidən qurma",
        },
        "VCS_SOURCE" => match lang {
            En => "Built from VCS HEAD (vcs+ source), not a pinned release",
            Tr => "VCS HEAD'den derleniyor (vcs+ kaynak), sabitlenmiş sürüm değil",
            Fr => "Construit depuis VCS HEAD (source vcs+), non figé",
            Es => "Compilado desde VCS HEAD (fuente vcs+), no una versión fija",
            Az => "VCS HEAD-dən qurulur (vcs+ mənbə), sabit buraxılış deyil",
        },
        "REVERSE_SHELL" => match lang {
            En => "Reverse-shell pattern detected",
            Tr => "Ters kabuk (reverse shell) deseni tespit edildi",
            Fr => "Motif de reverse shell détecté",
            Es => "Patrón de reverse shell detectado",
            Az => "Reverse shell nümunəsi aşkarlandı",
        },
        "SUID_BIT" => match lang {
            En => "Sets the setuid bit (privilege escalation risk)",
            Tr => "setuid biti ayarlıyor (yetki yükseltme riski)",
            Fr => "Définit le bit setuid (risque d'élévation de privilèges)",
            Es => "Establece el bit setuid (riesgo de escalada de privilegios)",
            Az => "setuid bitini təyin edir (imtiyaz yüksəltmə riski)",
        },
        "SYSTEM_PATH_WRITE" => match lang {
            En => "Writes outside the package dir into a system path: {}",
            Tr => "Paket dizini dışında bir sistem yoluna yazıyor: {}",
            Fr => "Écrit hors du répertoire du paquet, dans un chemin système : {}",
            Es => "Escribe fuera del directorio del paquete en una ruta del sistema: {}",
            Az => "Paket qovluğundan kənar sistem yoluna yazır: {}",
        },
        "HOME_PERSIST" => match lang {
            En => "Touches a user persistence path: {}",
            Tr => "Kullanıcı kalıcılık yoluna dokunuyor: {}",
            Fr => "Touche un chemin de persistance utilisateur : {}",
            Es => "Toca una ruta de persistencia del usuario: {}",
            Az => "İstifadəçi davamlılıq yoluna toxunur: {}",
        },
        "USER_MGMT" => match lang {
            En => "Modifies users/sudoers (account or privilege tampering)",
            Tr => "Kullanıcıları/sudoers'ı değiştiriyor (hesap/yetki kurcalama)",
            Fr => "Modifie les utilisateurs/sudoers (altération de comptes/privilèges)",
            Es => "Modifica usuarios/sudoers (manipulación de cuentas/privilegios)",
            Az => "İstifadəçiləri/sudoers-i dəyişir (hesab/imtiyaz manipulyasiyası)",
        },
        "DESTRUCTIVE" => match lang {
            En => "Destructive command detected (rm -rf / dd / mkfs / fork bomb)",
            Tr => "Yıkıcı komut tespit edildi (rm -rf / dd / mkfs / fork bomb)",
            Fr => "Commande destructrice détectée (rm -rf / dd / mkfs / fork bomb)",
            Es => "Comando destructivo detectado (rm -rf / dd / mkfs / fork bomb)",
            Az => "Dağıdıcı əmr aşkarlandı (rm -rf / dd / mkfs / fork bomb)",
        },
        "OBFUSCATION" => match lang {
            En => "Obfuscation pattern (hex escapes or ${IFS} splitting)",
            Tr => "Gizleme deseni (hex kaçışları veya ${IFS} ile bölme)",
            Fr => "Motif d'obfuscation (échappements hex ou découpe ${IFS})",
            Es => "Patrón de ofuscación (escapes hex o división ${IFS})",
            Az => "Gizlətmə nümunəsi (hex qaçışları və ya ${IFS} bölgüsü)",
        },
        "ANTI_FORENSIC" => match lang {
            En => "Anti-forensic command (history/log tampering)",
            Tr => "Adli analiz karşıtı komut (geçmiş/log kurcalama)",
            Fr => "Commande anti-forensique (altération historique/journaux)",
            Es => "Comando anti-forense (manipulación de historial/registros)",
            Az => "Anti-forensik əmr (tarixçə/log manipulyasiyası)",
        },
        "URL_SHORTENER" => match lang {
            En => "Source uses a URL shortener (hides the real host): {}",
            Tr => "Kaynak bir URL kısaltıcı kullanıyor (gerçek adresi gizler): {}",
            Fr => "La source utilise un raccourcisseur d'URL (masque l'hôte réel) : {}",
            Es => "La fuente usa un acortador de URL (oculta el host real): {}",
            Az => "Mənbə URL qısaldıcısı istifadə edir (əsl host-u gizlədir): {}",
        },
        "PYTHON_ENC_EXEC" => match lang {
            En => "Interpreter runs an encoded/inline payload (python -c / exec)",
            Tr => "Yorumlayıcı kodlanmış/satır içi yük çalıştırıyor (python -c / exec)",
            Fr => "L'interpréteur exécute une charge encodée/en ligne (python -c / exec)",
            Es => "El intérprete ejecuta una carga codificada/en línea (python -c / exec)",
            Az => "İnterpretator kodlanmış/sətirdaxili yük işlədir (python -c / exec)",
        },
        "CRYPTO_MINER" => match lang {
            En => "Cryptocurrency miner signature ({})",
            Tr => "Kripto para madenci imzası ({})",
            Fr => "Signature de mineur de cryptomonnaie ({})",
            Es => "Firma de minero de criptomonedas ({})",
            Az => "Kriptovalyuta mayner imzası ({})",
        },
        "DISCORD_EXFIL" => match lang {
            En => "Data exfiltration to a Discord webhook",
            Tr => "Discord webhook'una veri sızdırma",
            Fr => "Exfiltration de données vers un webhook Discord",
            Es => "Exfiltración de datos a un webhook de Discord",
            Az => "Discord webhook-a məlumat sızması",
        },
        "TELEGRAM_EXFIL" => match lang {
            En => "Data exfiltration via the Telegram bot API",
            Tr => "Telegram bot API'si ile veri sızdırma",
            Fr => "Exfiltration de données via l'API bot Telegram",
            Es => "Exfiltración de datos mediante la API de bots de Telegram",
            Az => "Telegram bot API vasitəsilə məlumat sızması",
        },
        "PASTE_PAYLOAD" => match lang {
            En => "Payload fetched from an ephemeral paste host: {}",
            Tr => "Geçici paste sunucusundan yük indiriliyor: {}",
            Fr => "Charge récupérée depuis un hébergeur de paste éphémère : {}",
            Es => "Carga descargada desde un host de paste efímero: {}",
            Az => "Müvəqqəti paste host-undan yük yüklənir: {}",
        },
        "SSH_KEY_INJECT" => match lang {
            En => "Writes an SSH authorized_keys entry (backdoor access)",
            Tr => "SSH authorized_keys girdisi yazıyor (arka kapı erişimi)",
            Fr => "Écrit une entrée SSH authorized_keys (accès par porte dérobée)",
            Es => "Escribe una entrada en authorized_keys de SSH (acceso por puerta trasera)",
            Az => "SSH authorized_keys girişi yazır (arxa qapı girişi)",
        },
        "CRON_PERSIST" => match lang {
            En => "Installs a cron job for persistence",
            Tr => "Kalıcılık için bir cron görevi kuruyor",
            Fr => "Installe une tâche cron pour la persistance",
            Es => "Instala una tarea cron para persistencia",
            Az => "Davamlılıq üçün cron tapşırığı quraşdırır",
        },
        "SYSTEMD_PERSIST" => match lang {
            En => "Enables or starts a systemd service from the build",
            Tr => "Derleme sırasında bir systemd servisini etkinleştiriyor/başlatıyor",
            Fr => "Active ou démarre un service systemd depuis la compilation",
            Es => "Habilita o inicia un servicio de systemd desde la compilación",
            Az => "Yığım zamanı systemd xidmətini aktivləşdirir/başladır",
        },
        "CRED_HARVEST" => match lang {
            En => "Reads sensitive credentials or keys ({})",
            Tr => "Hassas kimlik bilgilerini veya anahtarları okuyor ({})",
            Fr => "Lit des identifiants ou clés sensibles ({})",
            Es => "Lee credenciales o claves sensibles ({})",
            Az => "Həssas kimlik məlumatlarını və ya açarları oxuyur ({})",
        },
        "ENV_EXFIL" => match lang {
            En => "Sends environment or system secrets over the network",
            Tr => "Ortam değişkenlerini veya sistem sırlarını ağ üzerinden gönderiyor",
            Fr => "Envoie des variables d'environnement ou secrets système sur le réseau",
            Es => "Envía variables de entorno o secretos del sistema por la red",
            Az => "Mühit dəyişənlərini və ya sistem sirlərini şəbəkə üzərindən göndərir",
        },
        "DISABLE_SECURITY" => match lang {
            En => "Disables a security control ({})",
            Tr => "Bir güvenlik denetimini devre dışı bırakıyor ({})",
            Fr => "Désactive un contrôle de sécurité ({})",
            Es => "Desactiva un control de seguridad ({})",
            Az => "Təhlükəsizlik nəzarətini söndürür ({})",
        },
        "INSECURE_FETCH" => match lang {
            En => "Downloads with TLS verification disabled",
            Tr => "TLS doğrulaması kapalı şekilde indiriyor",
            Fr => "Télécharge avec la vérification TLS désactivée",
            Es => "Descarga con la verificación TLS desactivada",
            Az => "TLS yoxlaması söndürülmüş halda yükləyir",
        },
        "PIP_INDEX_HIJACK" => match lang {
            En => "Installs Python packages from a non-default index",
            Tr => "Python paketlerini varsayılan olmayan bir dizinden kuruyor",
            Fr => "Installe des paquets Python depuis un index non par défaut",
            Es => "Instala paquetes de Python desde un índice no predeterminado",
            Az => "Python paketlərini standart olmayan indeksdən quraşdırır",
        },
        "DECODED_THREAT" => match lang {
            En => "Encoded payload decodes to a known-bad pattern ({})",
            Tr => "Kodlanmış yük bilinen zararlı bir desene çözülüyor ({})",
            Fr => "La charge encodée se décode en un motif malveillant connu ({})",
            Es => "La carga codificada se decodifica en un patrón malicioso conocido ({})",
            Az => "Kodlanmış yük məlum zərərli nümunəyə açılır ({})",
        },
        "COMPRESSED_PAYLOAD" => match lang {
            En => "Encoded blob unwraps to a {} payload",
            Tr => "Kodlanmış blok bir {} yüküne açılıyor",
            Fr => "Le blob encodé se déballe en une charge {}",
            Es => "El blob codificado se desempaqueta en una carga {}",
            Az => "Kodlanmış blok {} yükünə açılır",
        },
        "ENCODED_BLOB" => match lang {
            En => "Encoded blob decodes to shell-like content",
            Tr => "Kodlanmış blok kabuk benzeri içeriğe çözülüyor",
            Fr => "Le blob encodé se décode en contenu de type shell",
            Es => "El blob codificado se decodifica en contenido tipo shell",
            Az => "Kodlanmış blok shell-bənzər məzmuna açılır",
        },
        "HIGH_ENTROPY_BLOB" => match lang {
            En => "High-entropy blob ({}); possible packed payload",
            Tr => "Yüksek entropili blok ({}); olası paketlenmiş yük",
            Fr => "Blob à haute entropie ({}) ; charge potentiellement empaquetée",
            Es => "Blob de alta entropía ({}); posible carga empaquetada",
            Az => "Yüksək entropiyalı blok ({}); ehtimal paketlənmiş yük",
        },
        "IOC_MATCH" => match lang {
            En => "Matches a known-bad indicator: {}",
            Tr => "Bilinen zararlı bir göstergeyle eşleşiyor: {}",
            Fr => "Correspond à un indicateur malveillant connu : {}",
            Es => "Coincide con un indicador malicioso conocido: {}",
            Az => "Məlum zərərli göstərici ilə uyğun gəlir: {}",
        },
        "WALLET_ADDRESS" => match lang {
            En => "Hardcoded crypto wallet address ({})",
            Tr => "Gömülü kripto cüzdan adresi ({})",
            Fr => "Adresse de portefeuille crypto codée en dur ({})",
            Es => "Dirección de billetera cripto incrustada ({})",
            Az => "Sabit kodlanmış kripto cüzdan ünvanı ({})",
        },
        "TAINTED_EXEC" => match lang {
            En => "Untrusted input in ${} reaches an execution sink",
            Tr => "${} içindeki güvenilmeyen girdi bir çalıştırma noktasına ulaşıyor",
            Fr => "Une entrée non fiable dans ${} atteint un point d'exécution",
            Es => "Entrada no confiable en ${} llega a un punto de ejecución",
            Az => "${} daxilindəki etibarsız giriş icra nöqtəsinə çatır",
        },
        "MAINTAINER_CHANGED" => match lang {
            En => "Maintainer changed since approval: {}",
            Tr => "Onaydan bu yana bakımcı değişti: {}",
            Fr => "Le mainteneur a changé depuis l'approbation : {}",
            Es => "El responsable cambió desde la aprobación: {}",
            Az => "Təsdiqdən sonra məsul şəxs dəyişdi: {}",
        },
        "DELTA_NEW_RISK" => match lang {
            En => "Version bump introduced new risk ({})",
            Tr => "Sürüm yükseltmesi yeni risk getirdi ({})",
            Fr => "La montée de version a introduit un nouveau risque ({})",
            Es => "El cambio de versión introdujo un nuevo riesgo ({})",
            Az => "Versiya yüksəlişi yeni risk gətirdi ({})",
        },
        "SCAN_PROFILE" => match lang {
            En => "Deep scan profile — decode/ioc/taint/delta enabled ({})",
            Tr => "Derin tarama profili — decode/ioc/taint/delta etkin ({})",
            Fr => "Profil d'analyse approfondie — decode/ioc/taint/delta activés ({})",
            Es => "Perfil de análisis profundo — decode/ioc/taint/delta activos ({})",
            Az => "Dərin tarama profili — decode/ioc/taint/delta aktiv ({})",
        },
        "EVASION_NORMALIZED" => match lang {
            En => "Obfuscated command revealed after normalization ({})",
            Tr => "Gizlenmiş komut normalleştirme sonrası ortaya çıktı ({})",
            Fr => "Commande obfusquée révélée après normalisation ({})",
            Es => "Comando ofuscado revelado tras la normalización ({})",
            Az => "Gizlədilmiş əmr normallaşdırmadan sonra aşkar edildi ({})",
        },
        "COMMITTED_BINARY" => match lang {
            En => "Prebuilt binary committed in the package tree: {}",
            Tr => "Paket ağacına gömülü önceden derlenmiş ikili dosya: {}",
            Fr => "Binaire précompilé présent dans l'arbre du paquet : {}",
            Es => "Binario precompilado incluido en el árbol del paquete: {}",
            Az => "Paket ağacına əlavə edilmiş öncədən qurulmuş ikili fayl: {}",
        },
        "PKGVER_EXEC" => match lang {
            En => "pkgver() runs code at build time ({})",
            Tr => "pkgver() derleme sırasında kod çalıştırıyor ({})",
            Fr => "pkgver() exécute du code lors de la compilation ({})",
            Es => "pkgver() ejecuta código durante la compilación ({})",
            Az => "pkgver() qurma zamanı kod icra edir ({})",
        },
        "MISSING_PGP" => match lang {
            En => "Source ships a PGP signature but no validpgpkeys is set (unverifiable)",
            Tr => "Kaynak PGP imzası içeriyor ama validpgpkeys tanımlı değil (doğrulanamaz)",
            Fr => "La source fournit une signature PGP mais validpgpkeys n'est pas défini (invérifiable)",
            Es => "La fuente trae una firma PGP pero no hay validpgpkeys (no verificable)",
            Az => "Mənbə PGP imzası gətirir, lakin validpgpkeys təyin edilməyib (yoxlanıla bilməz)",
        },
        "PGP_KEYSERVER_FETCH" => match lang {
            En => "Imports a PGP key from a keyserver at build time (unpinned trust)",
            Tr => "Derleme sırasında bir anahtar sunucusundan PGP anahtarı alıyor (sabitlenmemiş güven)",
            Fr => "Importe une clé PGP depuis un serveur de clés à la compilation (confiance non figée)",
            Es => "Importa una clave PGP de un servidor de claves al compilar (confianza no fijada)",
            Az => "Qurma zamanı açar serverindən PGP açarı idxal edir (sabitlənməmiş etibar)",
        },
        "LD_PRELOAD_HIJACK" => match lang {
            En => "Userland-rootkit LD_PRELOAD hijack ({})",
            Tr => "Kullanıcı-alanı rootkit LD_PRELOAD ele geçirme ({})",
            Fr => "Détournement LD_PRELOAD (rootkit en espace utilisateur) ({})",
            Es => "Secuestro LD_PRELOAD (rootkit en espacio de usuario) ({})",
            Az => "İstifadəçi-sahəsi rootkit LD_PRELOAD ələ keçirməsi ({})",
        },
        "SHELL_RC_PERSIST" => match lang {
            En => "Persistence via a shell startup file ({})",
            Tr => "Kabuk başlangıç dosyasıyla kalıcılık ({})",
            Fr => "Persistance via un fichier de démarrage du shell ({})",
            Es => "Persistencia mediante un archivo de inicio del shell ({})",
            Az => "Shell başlanğıc faylı ilə davamlılıq ({})",
        },
        "CLOUD_METADATA" => match lang {
            En => "Accesses a cloud instance-metadata endpoint ({})",
            Tr => "Bir bulut örnek-meta veri uç noktasına erişiyor ({})",
            Fr => "Accède à un point de métadonnées d'instance cloud ({})",
            Es => "Accede a un punto de metadatos de instancia en la nube ({})",
            Az => "Bulud instans-metadata son nöqtəsinə daxil olur ({})",
        },
        "DOCKER_SOCK" => match lang {
            En => "Container escape via the Docker socket",
            Tr => "Docker soketi üzerinden konteyner kaçışı",
            Fr => "Évasion de conteneur via le socket Docker",
            Es => "Fuga de contenedor a través del socket de Docker",
            Az => "Docker soketi vasitəsilə konteyner qaçışı",
        },
        "GIT_HOOK_PERSIST" => match lang {
            En => "Writes a git hook (runs on git operations)",
            Tr => "Bir git kancası yazıyor (git işlemlerinde çalışır)",
            Fr => "Écrit un hook git (s'exécute lors des opérations git)",
            Es => "Escribe un hook de git (se ejecuta en operaciones git)",
            Az => "Git hook yazır (git əməliyyatlarında işləyir)",
        },
        "SUDOERS_TAMPER" => match lang {
            En => "Modifies sudoers for privilege escalation ({})",
            Tr => "Yetki yükseltme için sudoers'ı değiştiriyor ({})",
            Fr => "Modifie sudoers pour une élévation de privilèges ({})",
            Es => "Modifica sudoers para escalar privilegios ({})",
            Az => "İmtiyaz yüksəltməsi üçün sudoers-i dəyişir ({})",
        },
        "CURL_FILE_UPLOAD" => match lang {
            En => "Uploads a local file off-host ({})",
            Tr => "Yerel bir dosyayı dışarı yüklüyor ({})",
            Fr => "Téléverse un fichier local vers l'extérieur ({})",
            Es => "Sube un archivo local fuera del host ({})",
            Az => "Yerli faylı xaricə yükləyir ({})",
        },
        "KERNEL_MODULE_LOAD" => match lang {
            En => "Loads a kernel module at build/install time ({})",
            Tr => "Derleme/kurulum sırasında çekirdek modülü yüklüyor ({})",
            Fr => "Charge un module noyau lors de la compilation/installation ({})",
            Es => "Carga un módulo del kernel al compilar/instalar ({})",
            Az => "Qurma/quraşdırma zamanı kernel modulu yükləyir ({})",
        },
        "TOR_C2" => match lang {
            En => "References a Tor hidden service (.onion) — possible C2",
            Tr => "Bir Tor gizli servisine (.onion) atıfta bulunuyor — olası C2",
            Fr => "Référence un service caché Tor (.onion) — C2 possible",
            Es => "Hace referencia a un servicio oculto de Tor (.onion) — posible C2",
            Az => "Tor gizli xidmətinə (.onion) istinad edir — ehtimal C2",
        },
        "PY_REVERSE_SHELL" => match lang {
            En => "Reverse shell via a scripting language ({})",
            Tr => "Bir betik dili üzerinden ters kabuk ({})",
            Fr => "Reverse shell via un langage de script ({})",
            Es => "Shell inverso mediante un lenguaje de scripting ({})",
            Az => "Skript dili vasitəsilə tərs shell ({})",
        },
        "AT_PERSIST" => match lang {
            En => "Schedules a job via at/batch ({})",
            Tr => "at/batch ile bir görev zamanlıyor ({})",
            Fr => "Planifie une tâche via at/batch ({})",
            Es => "Programa una tarea mediante at/batch ({})",
            Az => "at/batch ilə tapşırıq planlaşdırır ({})",
        },
        "DNS_EXFIL" => match lang {
            En => "Possible DNS-based data exfiltration",
            Tr => "Olası DNS tabanlı veri sızdırma",
            Fr => "Exfiltration de données possible via DNS",
            Es => "Posible exfiltración de datos basada en DNS",
            Az => "Ehtimal DNS əsaslı məlumat sızması",
        },
        "VT_HINT" => match lang {
            En => "Check this binary on VirusTotal: {}",
            Tr => "Bu ikiliyi VirusTotal'da kontrol et: {}",
            Fr => "Vérifiez ce binaire sur VirusTotal : {}",
            Es => "Verifica este binario en VirusTotal: {}",
            Az => "Bu ikili faylı VirusTotal-da yoxla: {}",
        },
        "VT_FLAGGED" => match lang {
            En => "VirusTotal flags this binary as malicious ({})",
            Tr => "VirusTotal bu ikiliyi zararlı olarak işaretliyor ({})",
            Fr => "VirusTotal signale ce binaire comme malveillant ({})",
            Es => "VirusTotal marca este binario como malicioso ({})",
            Az => "VirusTotal bu ikili faylı zərərli kimi işarələyir ({})",
        },
        "VT_CLEAN" => match lang {
            En => "VirusTotal: no engine flags this binary ({})",
            Tr => "VirusTotal: hiçbir motor bu ikiliyi işaretlemiyor ({})",
            Fr => "VirusTotal : aucun moteur ne signale ce binaire ({})",
            Es => "VirusTotal: ningún motor marca este binario ({})",
            Az => "VirusTotal: heç bir mühərrik bu ikili faylı işarələmir ({})",
        },
        "VT_UNKNOWN" => match lang {
            En => "VirusTotal has no record of this binary ({})",
            Tr => "VirusTotal'da bu ikiliye dair kayıt yok ({})",
            Fr => "VirusTotal n'a aucune trace de ce binaire ({})",
            Es => "VirusTotal no tiene registro de este binario ({})",
            Az => "VirusTotal-da bu ikili fayl haqqında qeyd yoxdur ({})",
        },
        "ORPHAN_PACKAGE" => match lang {
            En => "Package is orphaned (no maintainer)",
            Tr => "Paket sahipsiz (bakımcısı yok)",
            Fr => "Le paquet est orphelin (aucun mainteneur)",
            Es => "El paquete está huérfano (sin responsable)",
            Az => "Paket sahibsizdir (məsul şəxs yoxdur)",
        },
        "FLAGGED_OUTDATED" => match lang {
            En => "Flagged out-of-date ({})",
            Tr => "Güncel değil olarak işaretlenmiş ({})",
            Fr => "Signalé comme obsolète ({})",
            Es => "Marcado como desactualizado ({})",
            Az => "Köhnəlmiş kimi işarələnib ({})",
        },
        "VT_ERROR" => match lang {
            En => "VirusTotal lookup failed ({})",
            Tr => "VirusTotal sorgusu başarısız ({})",
            Fr => "Échec de la recherche VirusTotal ({})",
            Es => "La consulta a VirusTotal falló ({})",
            Az => "VirusTotal sorğusu uğursuz oldu ({})",
        },
        _ => return None,
    };
    Some(s)
}

/// Fill a localized template's single `{}` with `arg` (empty string if absent).
pub fn fill(template: &str, arg: Option<&str>) -> String {
    match template.split_once("{}") {
        Some((a, b)) => format!("{a}{}{b}", arg.unwrap_or("")),
        None => template.to_string(),
    }
}

/// The full localized `--help` / no-args screen. Flag and command *names* stay
/// in English (they are the actual CLI tokens); only the descriptions and
/// section headers are translated.
pub fn help_text(lang: Lang) -> String {
    // Section headers, then: 6 command/operation descriptions, 15 option
    // descriptions, 5 example captions, 3 exit-code explanations, and 2
    // `[files]`-section words. Every array's *index* means the same flag
    // across all five languages; see the `format!` below for the mapping.
    let (
        about,
        usage,
        commands_h,
        options_h,
        examples_h,
        exit_h,
        files_h,
        c,
        o,
        ex,
        exit_d,
        files_d,
    ) = match lang {
        Lang::En => (
            "AUR package security guard — analyze before you install.",
            "Usage",
            "Operations",
            "Options",
            "Examples",
            "Exit codes",
            "Files",
            [
                "Analyze and install AUR package(s)",
                "Show the security report only (no install)",
                "List packages installed via aurguard",
                "Analyze a local PKGBUILD (offline)",
                "Run the interactive setup wizard",
                "Fetch and install the latest signature ruleset",
            ],
            [
                "Interface language: en|tr|fr|es|az",
                "Disable colored output",
                "Output the report as JSON",
                "Auto-accept unless the fail-on threshold is met",
                "Block threshold: clean|risky|critical",
                "Maximum scrutiny: every deep pass at full sensitivity",
                "Verbose output (deep-scan profile + info findings)",
                "Disable the decode-and-rescan pass (base64/hex payloads)",
                "Disable the constant-fold anti-evasion pass",
                "Disable the IOC blocklist + crypto-wallet pass",
                "Disable the dataflow taint pass",
                "Disable version/maintainer delta tracking",
                "Look committed-binary hashes up on VirusTotal (needs a key)",
                "Print help",
                "Print version",
            ],
            [
                "Analyze and install",
                "Report only, never installs",
                "Lint your own PKGBUILD (offline, CI-friendly)",
                "CI gate: machine-readable, no color",
                "Update the signature ruleset",
            ],
            [
                "no findings",
                "warn-level findings, none critical",
                "at least one critical finding — blocked by default",
            ],
            [
                "optional",
                "external signature overlay — see --update-rules",
            ],
        ),
        Lang::Tr => (
            "AUR paket güvenlik bekçisi — kurmadan önce analiz et.",
            "Kullanım",
            "İşlemler",
            "Seçenekler",
            "Örnekler",
            "Çıkış kodları",
            "Dosyalar",
            [
                "AUR paket(ler)ini analiz et ve kur",
                "Yalnızca güvenlik raporunu göster (kurma)",
                "aurguard ile kurulan paketleri listele",
                "Yerel bir PKGBUILD analiz et (çevrimdışı)",
                "Etkileşimli kurulum sihirbazını çalıştır",
                "En güncel imza kümesini indir ve kur",
            ],
            [
                "Arayüz dili: en|tr|fr|es|az",
                "Renkli çıktıyı kapat",
                "Raporu JSON olarak ver",
                "Eşik aşılmadıkça otomatik kabul et",
                "Engelleme eşiği: clean|risky|critical",
                "En yüksek tarama: tüm derin geçişler tam duyarlılıkta",
                "Ayrıntılı çıktı (derin tarama profili + bilgi)",
                "Decode-and-rescan geçişini kapat (base64/hex veri)",
                "Sabit-katlama (anti-evasion) geçişini kapat",
                "IOC kara listesi + kripto cüzdan geçişini kapat",
                "Veri akışı (taint) geçişini kapat",
                "Versiyon/bakımcı değişim takibini kapat",
                "Commit edilmiş ikili dosya hash'lerini VirusTotal'da sorgula (anahtar gerekir)",
                "Yardımı göster",
                "Sürümü göster",
            ],
            [
                "Analiz et ve kur",
                "Sadece raporla, asla kurmaz",
                "Kendi PKGBUILD'ini denetle (çevrimdışı, CI-uyumlu)",
                "CI kapısı: makine-okunur, renksiz",
                "İmza kümesini güncelle",
            ],
            [
                "bulgu yok",
                "uyarı seviyesinde bulgu var, kritik yok",
                "en az bir kritik bulgu var — varsayılan olarak engellenir",
            ],
            ["opsiyonel", "dış imza katmanı — bkz. --update-rules"],
        ),
        Lang::Fr => (
            "Gardien de sécurité des paquets AUR — analysez avant d'installer.",
            "Utilisation",
            "Opérations",
            "Options",
            "Exemples",
            "Codes de sortie",
            "Fichiers",
            [
                "Analyser et installer des paquets AUR",
                "Afficher seulement le rapport (sans installer)",
                "Lister les paquets installés via aurguard",
                "Analyser un PKGBUILD local (hors ligne)",
                "Lancer l'assistant de configuration",
                "Récupérer et installer le dernier jeu de signatures",
            ],
            [
                "Langue de l'interface : en|tr|fr|es|az",
                "Désactiver la couleur",
                "Sortir le rapport en JSON",
                "Accepter sauf si le seuil fail-on est atteint",
                "Seuil de blocage : clean|risky|critical",
                "Analyse maximale : toutes les passes à pleine sensibilité",
                "Sortie détaillée (profil d'analyse + infos)",
                "Désactiver le décodage et la nouvelle analyse (base64/hex)",
                "Désactiver la passe anti-évasion (repliage de constantes)",
                "Désactiver la liste IOC + détection de portefeuille crypto",
                "Désactiver la passe d'analyse de flux de données (taint)",
                "Désactiver le suivi des changements de version/mainteneur",
                "Vérifier les hachages de binaires sur VirusTotal (clé requise)",
                "Afficher l'aide",
                "Afficher la version",
            ],
            [
                "Analyser et installer",
                "Rapport seulement, n'installe jamais",
                "Vérifiez votre propre PKGBUILD (hors ligne, adapté CI)",
                "Verrou CI : lisible par machine, sans couleur",
                "Mettre à jour le jeu de signatures",
            ],
            [
                "aucune découverte",
                "découvertes de niveau avertissement, aucune critique",
                "au moins une découverte critique — bloqué par défaut",
            ],
            [
                "optionnel",
                "surcouche de signatures externe — voir --update-rules",
            ],
        ),
        Lang::Es => (
            "Guardián de seguridad de paquetes AUR — analiza antes de instalar.",
            "Uso",
            "Operaciones",
            "Opciones",
            "Ejemplos",
            "Códigos de salida",
            "Archivos",
            [
                "Analizar e instalar paquete(s) de la AUR",
                "Mostrar solo el informe (sin instalar)",
                "Listar paquetes instalados con aurguard",
                "Analizar un PKGBUILD local (sin conexión)",
                "Ejecutar el asistente de configuración",
                "Descargar e instalar el conjunto de firmas más reciente",
            ],
            [
                "Idioma de la interfaz: en|tr|fr|es|az",
                "Desactivar el color",
                "Salida del informe en JSON",
                "Aceptar salvo que se alcance el umbral fail-on",
                "Umbral de bloqueo: clean|risky|critical",
                "Análisis máximo: todas las pasadas a plena sensibilidad",
                "Salida detallada (perfil de análisis + info)",
                "Desactivar la pasada de decodificación y reanálisis (base64/hex)",
                "Desactivar la pasada anti-evasión (plegado de constantes)",
                "Desactivar la lista IOC + detección de monederos cripto",
                "Desactivar la pasada de análisis de flujo de datos (taint)",
                "Desactivar el seguimiento de cambios de versión/mantenedor",
                "Consultar hashes de binarios en VirusTotal (requiere clave)",
                "Mostrar la ayuda",
                "Mostrar la versión",
            ],
            [
                "Analizar e instalar",
                "Solo informe, nunca instala",
                "Revisa tu propio PKGBUILD (sin conexión, apto para CI)",
                "Puerta de CI: legible por máquina, sin color",
                "Actualizar el conjunto de firmas",
            ],
            [
                "sin hallazgos",
                "hallazgos de nivel de advertencia, ninguno crítico",
                "al menos un hallazgo crítico — bloqueado por defecto",
            ],
            ["opcional", "capa de firmas externa — ver --update-rules"],
        ),
        Lang::Az => (
            "AUR paket təhlükəsizlik gözətçisi — quraşdırmadan əvvəl təhlil et.",
            "İstifadə",
            "Əməliyyatlar",
            "Seçimlər",
            "Nümunələr",
            "Çıxış kodları",
            "Fayllar",
            [
                "AUR paket(lər)ini təhlil et və quraşdır",
                "Yalnız təhlükəsizlik hesabatını göstər (quraşdırma)",
                "aurguard ilə quraşdırılan paketləri sadala",
                "Yerli PKGBUILD-i təhlil et (oflayn)",
                "İnteraktiv quraşdırma sehrbazını işlət",
                "Ən son imza dəstini yüklə və quraşdır",
            ],
            [
                "İnterfeys dili: en|tr|fr|es|az",
                "Rəngli çıxışı söndür",
                "Hesabatı JSON kimi ver",
                "Hədd keçilməyincə avtomatik qəbul et",
                "Bloklama həddi: clean|risky|critical",
                "Maksimum tarama: bütün dərin keçidlər tam həssaslıqda",
                "Ətraflı çıxış (dərin tarama profili + məlumat)",
                "Decode-and-rescan keçidini söndür (base64/hex)",
                "Sabit-qatlama (anti-evasion) keçidini söndür",
                "IOC qara siyahı + kripto pul kisəsi aşkarlamasını söndür",
                "Məlumat axını (taint) keçidini söndür",
                "Versiya/baxıcı dəyişikliyi izlənməsini söndür",
                "Commit edilmiş binar hash-lərini VirusTotal-da yoxla (açar lazımdır)",
                "Yardımı göstər",
                "Versiyanı göstər",
            ],
            [
                "Təhlil et və quraşdır",
                "Yalnız hesabat, heç vaxt quraşdırmır",
                "Öz PKGBUILD-ini yoxla (oflayn, CI-uyğun)",
                "CI qapısı: maşın-oxunaqlı, rəngsiz",
                "İmza dəstini yenilə",
            ],
            [
                "heç bir tapıntı yoxdur",
                "xəbərdarlıq səviyyəli tapıntılar var, kritik yoxdur",
                "ən azı bir kritik tapıntı var — defolt olaraq bloklanır",
            ],
            ["seçimlik", "xarici imza qatı — bax --update-rules"],
        ),
    };

    format!(
        "aurguard {ver} — {about}\n\
         \n{usage}: aurguard [OPTIONS] [COMMAND]\n\
         \n{commands_h}:\n\
         \x20 -S, --sync <PKG>...   {c0}\n\
         \x20 -I, --info <PKG>...   {c1}\n\
         \x20 -Q, --query           {c2}\n\
         \x20     --file <PATH>     {c3}\n\
         \x20     --setup           {c4}\n\
         \x20     --update-rules    {c5}\n\
         \x20     <PKG>...          (= -I; suggests matches if not found exactly)\n\
         \n{options_h}:\n\
         \x20     --lang <CODE>     {o0}\n\
         \x20     --no-color        {o1}\n\
         \x20     --json            {o2}\n\
         \x20     --skip-confirm    {o3}\n\
         \x20     --fail-on <SEV>   {o4}\n\
         \x20     --max             {o5}\n\
         \x20 -v, --verbose         {o6}\n\
         \x20     --no-decode       {o7}\n\
         \x20     --no-normalize    {o8}\n\
         \x20     --no-ioc          {o9}\n\
         \x20     --no-taint        {o10}\n\
         \x20     --no-delta        {o11}\n\
         \x20     --vt              {o12}\n\
         \x20 -h, --help            {o13}\n\
         \x20 -V, --version         {o14}\n\
         \n{examples_h}:\n\
         \x20 # {ex0}\n\
         \x20 aurguard -S yay\n\
         \x20 # {ex1}\n\
         \x20 aurguard -I some-package\n\
         \x20 # {ex2}\n\
         \x20 aurguard --file ./PKGBUILD --json\n\
         \x20 # {ex3}\n\
         \x20 aurguard -I yay --json --no-color\n\
         \x20 # {ex4}\n\
         \x20 aurguard --update-rules\n\
         \n{exit_h}:\n\
         \x20 0    CLEAN     — {exit0}\n\
         \x20 10   RISKY     — {exit1}\n\
         \x20 20   CRITICAL  — {exit2}\n\
         \n{files_h}:\n\
         \x20 ~/.config/aurguard/config.toml    ({files0})\n\
         \x20 ~/.config/aurguard/rules.d/*.toml  ({files1})\n\
         \n https://github.com/lunanoir21/aurguard-project\n",
        ver = env!("CARGO_PKG_VERSION"),
        c0 = c[0],
        c1 = c[1],
        c2 = c[2],
        c3 = c[3],
        c4 = c[4],
        c5 = c[5],
        o0 = o[0],
        o1 = o[1],
        o2 = o[2],
        o3 = o[3],
        o4 = o[4],
        o5 = o[5],
        o6 = o[6],
        o7 = o[7],
        o8 = o[8],
        o9 = o[9],
        o10 = o[10],
        o11 = o[11],
        o12 = o[12],
        o13 = o[13],
        o14 = o[14],
        ex0 = ex[0],
        ex1 = ex[1],
        ex2 = ex[2],
        ex3 = ex[3],
        ex4 = ex[4],
        exit0 = exit_d[0],
        exit1 = exit_d[1],
        exit2 = exit_d[2],
        files0 = files_d[0],
        files1 = files_d[1],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lang_roundtrip() {
        for l in Lang::ALL {
            assert_eq!(l.code().parse::<Lang>().unwrap(), l);
        }
    }

    #[test]
    fn parses_native_and_aliases() {
        assert_eq!("Türkçe".parse::<Lang>().unwrap(), Lang::Tr);
        assert_eq!("spanish".parse::<Lang>().unwrap(), Lang::Es);
        assert_eq!("AZ".parse::<Lang>().unwrap(), Lang::Az);
        assert!("klingon".parse::<Lang>().is_err());
    }

    #[test]
    fn every_lang_has_every_ui_key() {
        // Smoke: keys resolve to non-empty for all languages.
        let keys = [
            K::ReportTitle,
            K::LabelPackage,
            K::PromptInstall,
            K::WizTitle,
        ];
        for l in Lang::ALL {
            for &k in &keys {
                assert!(!t(l, k).is_empty());
            }
        }
    }

    #[test]
    fn finding_templates_localized() {
        assert!(finding(Lang::Tr, "EVAL").unwrap().contains("eval"));
        assert!(finding(Lang::Fr, "LOW_VOTES").unwrap().contains("{}"));
        assert!(finding(Lang::En, "NONEXISTENT").is_none());
    }

    #[test]
    fn fill_substitutes() {
        assert_eq!(fill("votes: {}", Some("5")), "votes: 5");
        assert_eq!(fill("no placeholder", Some("x")), "no placeholder");
    }
}
