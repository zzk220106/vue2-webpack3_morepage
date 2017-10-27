import Vue from 'vue'
import Router from 'vue-router'
import HelloWorld from '../components/twopage/HelloWorld.vue'

Vue.use(Router)

export default new Router({
  routes: [
    {
      path: '/',
      name: 'Hello',
      component: HelloWorld
    }
  ]
})
