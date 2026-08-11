<script setup lang="ts">
import { ref } from 'vue'
const rules = ref([{ id: 'secret-key', name: 'credential pattern', action: 'block', severity: 'high', enabled: true }])
</script>
<template>
  <section><h1>Rules</h1><table><thead><tr><th>Name</th><th>Action</th><th>Severity</th><th>Status</th></tr></thead><tbody><tr v-for="rule in rules" :key="rule.id"><td>{{ rule.name }}</td><td>{{ rule.action }}</td><td>{{ rule.severity }}</td><td>{{ rule.enabled ? 'enabled' : 'disabled' }}</td></tr></tbody></table></section>
</template>
