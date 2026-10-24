/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.amazon.sample.ui.web;

import com.amazon.sample.ui.config.EndpointProperties;
import com.amazon.sample.ui.services.catalog.CatalogService;
import com.amazon.sample.ui.web.util.RequiresCommonAttributes;
import java.util.Collections;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Controller
@RequestMapping("/catalog")
@Slf4j
@RequiresCommonAttributes
public class CatalogController {

  private static final Integer DEFAULT_PAGE = 1;
  private static final Integer DEFAULT_SIZE = 6;

  private CatalogService catalogService;

  private final EndpointProperties endpoints;

  public CatalogController(
    @Autowired CatalogService catalogService,
    @Autowired EndpointProperties endpoints
  ) {
    this.catalogService = catalogService;
    this.endpoints = endpoints;
  }

  @GetMapping("")
  public String catalog(
    @RequestParam(required = false, defaultValue = "") String tag,
    @RequestParam(required = false, defaultValue = "1") int page,
    @RequestParam(required = false, defaultValue = "6") int size,
    ServerHttpRequest request,
    Model model
  ) {
    model.addAttribute("tags", this.catalogService.getTags());
    model.addAttribute("selectedTag", tag);

    model.addAttribute(
      "catalog",
      catalogService.getProducts(tag, "", page, size)
    );

    return "catalog";
  }

  /**
   * POC WAF: puente hacia el endpoint vulnerable de Catalog. Reenvía el cuerpo JSON tal cual a
   * http://catalog/catalog/products y devuelve la respuesta (HTML con el name sin escapar).
   * No valida ni sanitiza nada a propósito: así el ataque llega al backend salvo que el WAF lo
   * frene. Se preserva la arquitectura Ingress -> WAF -> UI -> microservicio.
   */
  @PostMapping("/products")
  @ResponseBody
  public Mono<ResponseEntity<String>> createProduct(
    @RequestBody(required = false) String body
  ) {
    return WebClient.create(this.endpoints.getCatalog())
      .post()
      .uri("/catalog/products")
      .contentType(MediaType.APPLICATION_JSON)
      .bodyValue(body == null ? "" : body)
      .exchangeToMono(response ->
        response
          .bodyToMono(String.class)
          .defaultIfEmpty("")
          .map(responseBody ->
            ResponseEntity.status(response.statusCode()).body(responseBody)
          )
      );
  }

  @GetMapping("/{id}")
  public String item(
    @PathVariable String id,
    ServerHttpRequest request,
    Model model
  ) {
    model.addAttribute("item", catalogService.getProduct(id));
    model.addAttribute(
      "recommendations",
      catalogService
        .getProducts("", "", DEFAULT_PAGE, DEFAULT_SIZE)
        .map(p -> {
          Collections.shuffle(p.getProducts());
          return p.getProducts();
        })
        .flatMapMany(Flux::fromIterable)
    );

    return "detail";
  }
}
