package io.mikael.poc

import org.springframework.web.bind.annotation.GetMapping

import org.springframework.web.bind.annotation.RestController
import java.time.LocalTime
import java.time.format.DateTimeFormatter


@RestController
class TimeController {

    @GetMapping("/time")
    fun retrieveTime(): String {
        val dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss")
        val localTime: LocalTime = LocalTime.now()
        return dateTimeFormatter.format(localTime)
    }

}
