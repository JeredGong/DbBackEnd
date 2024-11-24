DROP TABLE IF EXISTS public.docs;
DROP TABLE IF EXISTS public.buff;
DROP TABLE IF EXISTS public.recs;
DROP TABLE IF EXISTS public.logs;
DROP TABLE IF EXISTS public.user;
DROP TABLE IF EXISTS public.book;
DROP SEQUENCE IF EXISTS public.user_id_seq;
DROP SEQUENCE IF EXISTS public.docs_id_seq;
DROP SEQUENCE IF EXISTS public.buff_id_seq;
DROP SEQUENCE IF EXISTS public.book_id_seq;
DROP SEQUENCE IF EXISTS public.recs_id_seq;
DROP SEQUENCE IF EXISTS public.logs_id_seq;

-- user: Information of users

	-- user_id_seq
	
	CREATE SEQUENCE IF NOT EXISTS public.user_id_seq
	    INCREMENT 1
	    START 1
	    MINVALUE 1
	    MAXVALUE 9223372036854775807
	    CACHE 1;
	
	ALTER SEQUENCE public.user_id_seq
	    OWNER TO postgres;

CREATE TABLE IF NOT EXISTS public.user
(
    id bigint NOT NULL DEFAULT nextval('user_id_seq'::regclass),
    username character varying(256) COLLATE pg_catalog."default",
    password_hash character varying(512) COLLATE pg_catalog."default",
	email character varying(256) COLLATE pg_catalog."default",
    role smallint,
    image text,
    CONSTRAINT user_pkey PRIMARY KEY (id),
    CONSTRAINT name_unique UNIQUE (username),
	CONSTRAINT email_unique UNIQUE (email)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.user
    OWNER to postgres;

INSERT INTO public.user(username, password_hash, role)
	VALUES ('admin', 'admin', 0);

INSERT INTO public.user(username, password_hash, role)
	VALUES ('user', 'user', 1);


-- docs: Information of documents

	-- docs_id_seq
	
	CREATE SEQUENCE IF NOT EXISTS public.docs_id_seq
	    INCREMENT 1
	    START 1
	    MINVALUE 1
	    MAXVALUE 9223372036854775807
	    CACHE 1;
	
	ALTER SEQUENCE public.docs_id_seq
	    OWNER TO postgres;

CREATE TABLE IF NOT EXISTS public.docs
(
    id bigint NOT NULL DEFAULT nextval('docs_id_seq'::regclass),
    title character varying(256) COLLATE pg_catalog."default",
    file_path text,
    uploaded_by bigint,
    download_count integer,
    upload_time timestamp with time zone,
	doc_type character varying(128),
	author character varying(128),
	publish_date date,
    CONSTRAINT docs_pkey PRIMARY KEY (id),
	CONSTRAINT docs_unique UNIQUE (file_path),
    CONSTRAINT uploaded_by_exist FOREIGN KEY (uploaded_by)
        REFERENCES public."user" (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.docs
    OWNER to postgres;


-- buff: Buffer of uploaded documents

	-- buff_id_seq
	
	CREATE SEQUENCE IF NOT EXISTS public.buff_id_seq
	    INCREMENT 1
	    START 1
	    MINVALUE 1
	    MAXVALUE 9223372036854775807
	    CACHE 1;
	
	ALTER SEQUENCE public.buff_id_seq
	    OWNER TO postgres;

CREATE TABLE IF NOT EXISTS public.buff
(
    id bigint NOT NULL DEFAULT nextval('buff_id_seq'::regclass),
    title character varying(256) COLLATE pg_catalog."default",
    file_path text,
    uploaded_by bigint,
    download_count integer,
    upload_time timestamp with time zone,
	doc_type character varying(128),
	author character varying(128),
	publish_date date,
    CONSTRAINT buff_pkey PRIMARY KEY (id),
	CONSTRAINT buff_unique UNIQUE (file_path),
    CONSTRAINT uploaded_by_exist FOREIGN KEY (uploaded_by)
        REFERENCES public."user" (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
        NOT VALID
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.buff
    OWNER to postgres;

	
-- book: Information of books

	-- book_id_seq;
	
	CREATE SEQUENCE IF NOT EXISTS public.book_id_seq
	    INCREMENT 1
	    START 1
	    MINVALUE 1
	    MAXVALUE 9223372036854775807
	    CACHE 1;
	
	ALTER SEQUENCE public.book_id_seq
	    OWNER TO postgres;

CREATE TABLE IF NOT EXISTS public.book
(
    id bigint NOT NULL DEFAULT nextval('book_id_seq'::regclass),
    title character varying(256) COLLATE pg_catalog."default",
    author character varying(128) COLLATE pg_catalog."default",
	book_type character varying(128) COLLATE pg_catalog."default",
	publish_date date,
    available boolean,
    CONSTRAINT book_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.book
    OWNER to postgres;


-- recs: Information of records of borrowing

	-- recs_id_seq;
	
	CREATE SEQUENCE IF NOT EXISTS public.recs_id_seq
	    INCREMENT 1
	    START 1
	    MINVALUE 1
	    MAXVALUE 9223372036854775807
	    CACHE 1;
	
	ALTER SEQUENCE public.recs_id_seq
	    OWNER TO postgres;

CREATE TABLE IF NOT EXISTS public.recs
(
    id bigint NOT NULL DEFAULT nextval('recs_id_seq'::regclass),
    user_id bigint NOT NULL,
    book_id bigint NOT NULL,
    borrowed_at timestamp with time zone,
    returned_at timestamp with time zone,
    CONSTRAINT recs_pkey PRIMARY KEY (id),
    CONSTRAINT book_id_exist FOREIGN KEY (book_id)
        REFERENCES public.book (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION,
    CONSTRAINT user_id_exist FOREIGN KEY (user_id)
        REFERENCES public."user" (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.recs
    OWNER to postgres;


-- logs: Information of logs

	-- logs_id_seq;
	
	CREATE SEQUENCE IF NOT EXISTS public.logs_id_seq
	    INCREMENT 1
	    START 1
	    MINVALUE 1
	    MAXVALUE 9223372036854775807
	    CACHE 1;
	
	ALTER SEQUENCE public.logs_id_seq
	    OWNER TO postgres;
		
CREATE TABLE IF NOT EXISTS public.logs
(
    id bigint NOT NULL DEFAULT nextval('logs_id_seq'::regclass),
    user_id bigint,
    action character varying(512) COLLATE pg_catalog."default",
	log_time timestamp with time zone,
    CONSTRAINT logs_pkey PRIMARY KEY (id),
    CONSTRAINT user_id_exist FOREIGN KEY (user_id)
        REFERENCES public."user" (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE NO ACTION
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.logs
    OWNER to postgres;
