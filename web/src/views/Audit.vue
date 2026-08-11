<script setup lang="ts">
const audits = [
  { id: 'demo-001', path: '/v1/chat/completions', score: 85, decision: 'blocked' },
]
</script>
<template>
  <section><h1>Audit events</h1><table><thead><tr><th>ID</th><th>Path</th><th>Risk</th><th>Decision</th></tr></thead><tbody><tr v-for="audit in audits" :key="audit.id"><td>{{ audit.id }}</td><td>{{ audit.path }}</td><td>{{ audit.score }}</td><td>{{ audit.decision }}</td></tr></tbody></table></section>
</template>
