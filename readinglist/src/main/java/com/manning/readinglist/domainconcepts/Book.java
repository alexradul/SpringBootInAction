/*
* This code has been generated by the Rebel: a Model Driven Development Toolkit for Java,
* provided by the Archetype Software Engineering.
*
* Drop us a mail at contact@archetypesoftware.com or visit www.archetypesoftware.com
* if you need additional information or have any questions.
*/
package com.manning.readinglist.domainconcepts;

import java.util.*;
import java.time.*;

import javax.persistence.*;
import javax.validation.constraints.*;


// ----------- << preserved-imports
// ----------- >>

@Entity
// ----------- << AAAAAAFiblU/qnPuW3U=>annotations
// ----------- >>
public class Book {
    // ----------- << AAAAAAFiblU/qnPuW3U=>id
    // ----------- >>
    @Id
    @GeneratedValue(strategy=GenerationType.AUTO)
    private Long id;

    // ----------- << AAAAAAFiblU/qnPuW3U=>version
    // ----------- >>
    @Version
    private Long version;

    @NotNull
    @Column(nullable=false)
    // ----------- << AAAAAAFible7D3QfDEY=>annotations
    // ----------- >>
    private String title;

    @NotNull
    @Column(nullable=false)
    // ----------- << AAAAAAFiblfJ53Qmwfk=>annotations
    // ----------- >>
    private String author;

    @NotNull
    @Column(nullable=false)
    // ----------- << AAAAAAFiblfZ0nQtp2M=>annotations
    // ----------- >>
    private String reader;

    @NotNull
    @Column(nullable=false)
    // ----------- << AAAAAAFiblfk8XQ0e08=>annotations
    // ----------- >>
    private String isbn;

    // ----------- << AAAAAAFiblU/qnPuW3U=>getId
    // ----------- >>
    public Long getId(){
        return id;
    }

    public String getTitle() {
        return title;
    }

    public String getAuthor() {
        return author;
    }

    public String getReader() {
        return reader;
    }

    public String getIsbn() {
        return isbn;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public void setReader(String reader) {
        this.reader = reader;
    }

    public void setIsbn(String isbn) {
        this.isbn = isbn;
    }

    // ----------- << AAAAAAFiblU/qnPuW3U=>equals
    // ----------- >>
    @Override
    public boolean equals(Object obj) {
        if (super.equals(obj)) return true;
        if (getId() == 0) return false;
        if (!(obj instanceof Book)) return false;

        return (getId() == ((Book) obj).getId());
    }

// ----------- << AAAAAAFiblU/qnPuW3U=>class-extras
// ----------- >>
}