// NumaSec - PTES Penetration Test Report Template
// ═══════════════════════════════════════════════════════════════════════════════

// Document Configuration
#set document(
  title: "{{title}}",
  author: "{{author}}",
)

#set page(
  paper: "a4",
  margin: (x: 2cm, y: 2.5cm),
  header: context {
    if counter(page).get().first() > 1 [
      #text(size: 9pt, fill: rgb("#666666"))[
        #h(1fr)
        {{client_name}} - Penetration Test Report
        #h(1fr)
        #text(fill: rgb("#cc0000"))[{{classification}}]
      ]
      #line(length: 100%, stroke: 0.5pt + rgb("#cccccc"))
    ]
  },
  footer: context [
    #line(length: 100%, stroke: 0.5pt + rgb("#cccccc"))
    #text(size: 9pt, fill: rgb("#666666"))[
      NumaSec
      #h(1fr)
      Page #counter(page).display() of #context counter(page).final().first()
    ]
  ],
)

#set text(
  font: "Noto Sans",
  size: 11pt,
  lang: "en",
)

#set heading(numbering: "1.1.1")

#show heading.where(level: 1): it => {
  pagebreak(weak: true)
  text(size: 18pt, weight: "bold", fill: rgb("#1a1a2e"))[#it]
  v(0.5em)
}

#show heading.where(level: 2): it => {
  v(1em)
  text(size: 14pt, weight: "bold", fill: rgb("#16213e"))[#it]
  v(0.3em)
}

#show heading.where(level: 3): it => {
  v(0.5em)
  text(size: 12pt, weight: "bold", fill: rgb("#0f3460"))[#it]
  v(0.2em)
}

// Severity badge function
#let severity-badge(severity) = {
  let (bg-color, text-color) = if severity == "Critical" {
    (rgb("#8B0000"), white)
  } else if severity == "High" {
    (rgb("#FF4500"), white)
  } else if severity == "Medium" {
    (rgb("#FFA500"), black)
  } else if severity == "Low" {
    (rgb("#32CD32"), black)
  } else {
    (rgb("#1E90FF"), white)
  }
  box(
    fill: bg-color,
    inset: (x: 6pt, y: 3pt),
    radius: 3pt,
    text(fill: text-color, weight: "bold", size: 9pt)[#severity]
  )
}

// CVSS score badge
#let cvss-badge(score) = {
  let bg-color = if score >= 9.0 {
    rgb("#8B0000")
  } else if score >= 7.0 {
    rgb("#FF4500")
  } else if score >= 4.0 {
    rgb("#FFA500")
  } else if score > 0 {
    rgb("#32CD32")
  } else {
    rgb("#808080")
  }
  box(
    fill: bg-color,
    inset: (x: 6pt, y: 3pt),
    radius: 3pt,
    text(fill: white, weight: "bold", size: 9pt)[CVSS: #score]
  )
}

// Info box
#let info-box(title, content) = {
  block(
    fill: rgb("#f0f4f8"),
    stroke: (left: 3pt + rgb("#3498db")),
    inset: 10pt,
    width: 100%,
    [
      #text(weight: "bold", fill: rgb("#2c3e50"))[#title]
      #v(0.3em)
      #content
    ]
  )
}

// Warning box
#let warning-box(title, content) = {
  block(
    fill: rgb("#fff3cd"),
    stroke: (left: 3pt + rgb("#ffc107")),
    inset: 10pt,
    width: 100%,
    [
      #text(weight: "bold", fill: rgb("#856404"))[⚠ #title]
      #v(0.3em)
      #content
    ]
  )
}

// Critical box
#let critical-box(title, content) = {
  block(
    fill: rgb("#f8d7da"),
    stroke: (left: 3pt + rgb("#dc3545")),
    inset: 10pt,
    width: 100%,
    [
      #text(weight: "bold", fill: rgb("#721c24"))[🔴 #title]
      #v(0.3em)
      #content
    ]
  )
}

// Code block
#let code-block(code, lang: none) = {
  block(
    fill: rgb("#2d2d2d"),
    inset: 10pt,
    radius: 4pt,
    width: 100%,
    text(fill: rgb("#f8f8f2"), font: "JetBrains Mono", size: 9pt)[#raw(code)]
  )
}


// ═══════════════════════════════════════════════════════════════════════════════
// COVER PAGE
// ═══════════════════════════════════════════════════════════════════════════════

#page(
  header: none,
  footer: none,
  background: {
    place(top + left, rect(width: 100%, height: 35%, fill: rgb("#1a1a2e")))
  }
)[
  #v(3cm)
  
  #align(center)[
    #text(size: 32pt, weight: "bold", fill: white)[
      Penetration Test Report
    ]
    
    #v(0.5cm)
    
    #text(size: 18pt, fill: rgb("#e94560"))[
      {{client_name}}
    ]
    
    #v(0.3cm)
    
    #text(size: 14pt, fill: rgb("#cccccc"))[
      {{project_name}}
    ]
  ]
  
  #v(4cm)
  
  #align(center)[
    #box(
      fill: rgb("#e94560"),
      inset: (x: 20pt, y: 10pt),
      radius: 5pt,
      text(fill: white, weight: "bold", size: 14pt)[{{classification}}]
    )
  ]
  
  #v(3cm)
  
  #block(
    width: 100%,
    inset: 20pt,
  )[
    #grid(
      columns: (1fr, 1fr),
      gutter: 20pt,
      [
        #text(weight: "bold", fill: rgb("#666666"))[Report Details]
        #v(0.5em)
        #table(
          columns: (auto, 1fr),
          stroke: none,
          inset: 5pt,
          [*Version:*], [{{version}}],
          [*Date:*], [{{report_date}}],
          [*Status:*], [{{status}}],
        )
      ],
      [
        #text(weight: "bold", fill: rgb("#666666"))[Engagement Period]
        #v(0.5em)
        #table(
          columns: (auto, 1fr),
          stroke: none,
          inset: 5pt,
          [*Start:*], [{{start_date}}],
          [*End:*], [{{end_date}}],
          [*Duration:*], [{{duration}} days],
        )
      ]
    )
  ]
  
  #v(1fr)
  
  #align(center)[
    #text(size: 10pt, fill: rgb("#999999"))[
      Generated by NumaSec
    ]
  ]
]


// ═══════════════════════════════════════════════════════════════════════════════
// DOCUMENT CONTROL
// ═══════════════════════════════════════════════════════════════════════════════

= Document Control

#table(
  columns: (1fr, 2fr),
  inset: 10pt,
  fill: (col, row) => if row == 0 { rgb("#f0f4f8") } else { none },
  stroke: 0.5pt + rgb("#cccccc"),
  [*Document Title*], [{{title}}],
  [*Client*], [{{client_name}}],
  [*Project*], [{{project_name}}],
  [*Version*], [{{version}}],
  [*Classification*], [{{classification}}],
  [*Author*], [{{author}}],
  [*Reviewer*], [{{reviewer}}],
  [*Date*], [{{report_date}}],
)

#v(1em)

== Version History

#table(
  columns: (auto, auto, 1fr, auto),
  inset: 8pt,
  fill: (col, row) => if row == 0 { rgb("#f0f4f8") } else { none },
  stroke: 0.5pt + rgb("#cccccc"),
  [*Version*], [*Date*], [*Changes*], [*Author*],
  {{#each version_history}}
  [{{version}}], [{{date}}], [{{changes}}], [{{author}}],
  {{/each}}
)

== Distribution List

#table(
  columns: (1fr, 1fr, auto),
  inset: 8pt,
  fill: (col, row) => if row == 0 { rgb("#f0f4f8") } else { none },
  stroke: 0.5pt + rgb("#cccccc"),
  [*Name*], [*Role*], [*Organization*],
  {{#each distribution_list}}
  [{{name}}], [{{role}}], [{{organization}}],
  {{/each}}
)


// ═══════════════════════════════════════════════════════════════════════════════
// TABLE OF CONTENTS
// ═══════════════════════════════════════════════════════════════════════════════

= Table of Contents

#outline(
  title: none,
  indent: 2em,
  depth: 3,
)


// ═══════════════════════════════════════════════════════════════════════════════
// EXECUTIVE SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

= Executive Summary

== Overview

{{executive_summary}}

== Scope

The assessment covered the following assets:

{{#each scope_items}}
- {{this}}
{{/each}}

== Key Findings Summary

#align(center)[
  #table(
    columns: (1fr, 1fr, 1fr, 1fr, 1fr),
    inset: 12pt,
    fill: (col, row) => {
      if row == 0 { rgb("#1a1a2e") }
      else if col == 0 { rgb("#8B0000").lighten(80%) }
      else if col == 1 { rgb("#FF4500").lighten(80%) }
      else if col == 2 { rgb("#FFA500").lighten(80%) }
      else if col == 3 { rgb("#32CD32").lighten(80%) }
      else { rgb("#1E90FF").lighten(80%) }
    },
    stroke: 0.5pt + rgb("#cccccc"),
    text(fill: white, weight: "bold")[Critical],
    text(fill: white, weight: "bold")[High],
    text(fill: white, weight: "bold")[Medium],
    text(fill: white, weight: "bold")[Low],
    text(fill: white, weight: "bold")[Info],
    text(size: 18pt, weight: "bold")[{{critical_count}}],
    text(size: 18pt, weight: "bold")[{{high_count}}],
    text(size: 18pt, weight: "bold")[{{medium_count}}],
    text(size: 18pt, weight: "bold")[{{low_count}}],
    text(size: 18pt, weight: "bold")[{{info_count}}],
  )
]

== Risk Rating

Based on our assessment, the overall security posture is rated as:

#align(center)[
  #box(
    fill: {{overall_risk_color}},
    inset: (x: 30pt, y: 15pt),
    radius: 5pt,
    text(fill: white, weight: "bold", size: 20pt)[{{overall_risk}}]
  )
]

== Key Recommendations

{{#each key_recommendations}}
#block(inset: (left: 15pt))[
  #{counter("rec").step()}
  #counter("rec").display(). #text(weight: "bold")[{{title}}]
  
  {{description}}
]
{{/each}}


// ═══════════════════════════════════════════════════════════════════════════════
// METHODOLOGY
// ═══════════════════════════════════════════════════════════════════════════════

= Methodology

== Penetration Testing Execution Standard (PTES)

This assessment followed the Penetration Testing Execution Standard (PTES), which consists of seven phases:

#table(
  columns: (auto, 1fr, auto),
  inset: 10pt,
  fill: (col, row) => if row == 0 { rgb("#f0f4f8") } else { none },
  stroke: 0.5pt + rgb("#cccccc"),
  [*Phase*], [*Description*], [*Status*],
  [1. Pre-engagement], [Scope definition and authorization], [✅],
  [2. Intelligence Gathering], [Information collection and reconnaissance], [✅],
  [3. Threat Modeling], [Attack surface analysis], [✅],
  [4. Vulnerability Analysis], [Vulnerability identification and validation], [✅],
  [5. Exploitation], [Controlled exploitation of vulnerabilities], [✅],
  [6. Post Exploitation], [Impact assessment and persistence testing], [✅],
  [7. Reporting], [Documentation and recommendations], [✅],
)

== Tools Used

The following tools were utilized during this assessment:

#table(
  columns: (1fr, 2fr),
  inset: 8pt,
  fill: (col, row) => if row == 0 { rgb("#f0f4f8") } else { none },
  stroke: 0.5pt + rgb("#cccccc"),
  [*Tool*], [*Purpose*],
  {{#each tools_used}}
  [{{name}}], [{{purpose}}],
  {{/each}}
)

== Testing Approach

{{testing_approach}}


// ═══════════════════════════════════════════════════════════════════════════════
// DETAILED FINDINGS
// ═══════════════════════════════════════════════════════════════════════════════

= Detailed Findings

{{#each findings}}

== Finding {{@index}}: {{title}}

#grid(
  columns: (auto, 1fr, auto, auto),
  gutter: 10pt,
  align: (left, left, right, right),
  severity-badge("{{severity}}"),
  [],
  cvss-badge({{cvss_score}}),
  text(size: 9pt, fill: rgb("#666666"))[{{cwe_id}}],
)

#v(0.5em)

=== Description

{{description}}

=== Affected Assets

{{#each affected_assets}}
- `{{this}}`
{{/each}}

=== Evidence

{{#each evidence}}
#block(
  fill: rgb("#f8f8f8"),
  inset: 10pt,
  radius: 4pt,
  width: 100%,
)[
  #text(weight: "bold", size: 10pt)[{{title}}]
  
  {{description}}
  
  {{#if code}}
  #code-block("{{code}}")
  {{/if}}
]
{{/each}}

=== Impact

{{impact}}

=== CVSS Vector

#text(font: "JetBrains Mono", size: 9pt)[{{cvss_vector}}]

=== Remediation

#info-box("Recommended Fix")[
  {{remediation}}
]

=== References

{{#each references}}
- {{this}}
{{/each}}

#line(length: 100%, stroke: 0.5pt + rgb("#cccccc"))

{{/each}}


// ═══════════════════════════════════════════════════════════════════════════════
// REMEDIATION ROADMAP
// ═══════════════════════════════════════════════════════════════════════════════

= Remediation Roadmap

== Priority Matrix

#table(
  columns: (auto, 1fr, auto, auto),
  inset: 10pt,
  fill: (col, row) => if row == 0 { rgb("#f0f4f8") } else { none },
  stroke: 0.5pt + rgb("#cccccc"),
  [*Priority*], [*Finding*], [*Effort*], [*Timeline*],
  {{#each remediation_roadmap}}
  [{{priority}}], [{{finding}}], [{{effort}}], [{{timeline}}],
  {{/each}}
)

== Implementation Guidance

{{#each implementation_guidance}}
=== {{title}}

{{description}}

{{/each}}


// ═══════════════════════════════════════════════════════════════════════════════
// APPENDICES
// ═══════════════════════════════════════════════════════════════════════════════

= Appendices

== Appendix A: Scope Details

#table(
  columns: (auto, 1fr, auto),
  inset: 8pt,
  fill: (col, row) => if row == 0 { rgb("#f0f4f8") } else { none },
  stroke: 0.5pt + rgb("#cccccc"),
  [*Type*], [*Target*], [*Status*],
  {{#each scope_details}}
  [{{type}}], [{{target}}], [{{status}}],
  {{/each}}
)

== Appendix B: Raw Scan Data

_Raw scan outputs and detailed technical data are available upon request._

== Appendix C: CVSS 3.1 Scoring Guide

#table(
  columns: (auto, auto, 1fr),
  inset: 8pt,
  fill: (col, row) => if row == 0 { rgb("#f0f4f8") } else { none },
  stroke: 0.5pt + rgb("#cccccc"),
  [*Score Range*], [*Severity*], [*Description*],
  [9.0 - 10.0], [Critical], [Exploitation is straightforward and impact is severe],
  [7.0 - 8.9], [High], [Exploitation requires some effort but impact is significant],
  [4.0 - 6.9], [Medium], [Exploitation requires significant effort or impact is limited],
  [0.1 - 3.9], [Low], [Exploitation is difficult and/or impact is minimal],
  [0.0], [None], [No security impact],
)


// ═══════════════════════════════════════════════════════════════════════════════
// END OF REPORT
// ═══════════════════════════════════════════════════════════════════════════════

#v(2cm)

#align(center)[
  #line(length: 50%, stroke: 1pt + rgb("#1a1a2e"))
  
  #v(0.5cm)
  
  #text(size: 10pt, fill: rgb("#666666"))[
    End of Report
    
    Generated by NumaSec
    
    {{report_date}}
  ]
]
