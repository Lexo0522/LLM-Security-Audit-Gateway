<script setup lang="ts">
const stats = [
  { label: 'Requests', value: '0' },
  { label: 'Blocked', value: '0' },
  { label: 'P95 latency', value: '0ms' },
]
</script>
<template>
  <section><h1>Dashboard</h1><div class="stats"><article v-for="stat in stats" :key="stat.label"><strong>{{ stat.value }}</strong><span>{{ stat.label }}</span></article></div></section>
</template>
