import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import HomeContent from './HomeContent.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('HomeContent', HomeContent)
  },
} satisfies Theme
