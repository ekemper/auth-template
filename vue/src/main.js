import Vue from 'vue'
import App from './App.vue'

Vue.config.productionTip = false

import GoogleSigninButton from '@/components/GoogleSigninButton'
Vue.component('g-signin-button', GoogleSigninButton)


new Vue({
  render: h => h(App),
}).$mount('#app')