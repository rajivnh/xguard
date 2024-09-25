package com.lti.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HomeController {

	@ResponseBody
	@GetMapping("/")
	public String index() {
		UserDetails userDetails = ((UserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal());
		
		return userDetails.getUsername() + " Successfully Signed In";
	}
	
	@GetMapping("/login")
	public String login() {
		return "login";
	}
}
