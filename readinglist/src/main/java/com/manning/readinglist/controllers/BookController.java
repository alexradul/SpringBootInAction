/*
* This code has been generated by the Rebel: a Model Driven Development Toolkit for Java,
* provided by the Archetype Software Engineering.
*
* Drop us a mail at contact@archetypesoftware.com or visit www.archetypesoftware.com
* if you need additional information or have any questions.
*/
package com.manning.readinglist.controllers;

import java.util.*;
import java.time.*;

import org.springframework.stereotype.Controller;

import com.manning.readinglist.domainconcepts.Book;
// ----------- << preserved-imports
import com.manning.readinglist.repositories.BookRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
// ----------- >>

/**
* Controller for the Book concept.
*/

@RequestMapping("/")
@Controller
// ----------- << AAAAAAFibltVb3RBh+A=>annotations
// ----------- >>
public class BookController {
    /**
    * @param reader 
    * @param model
    */

    @GetMapping(value="/{reader}")
    // ----------- << AAAAAAFiblx0pXRxF5o=>annotations
    // ----------- >>
    public String readersBooks(@PathVariable("reader") String reader, Model model) {
    // ----------- << AAAAAAFiblx0pXRxF5o=>method
    // ----------- >>
    }
    /**
    * @param reader 
    * @param book
    */

    @PostMapping("/{reader}")
    // ----------- << AAAAAAFibmKMZ3SHQCU=>annotations
    // ----------- >>
    public String addToReadingList(@PathVariable("reader") String reader, Book book) {
    // ----------- << AAAAAAFibmKMZ3SHQCU=>method
    // ----------- >>
    }
// ----------- << AAAAAAFibltVb3RBh+A=>class-extras
    @Autowired
    BookRepository bookRepository;
// ----------- >>
}